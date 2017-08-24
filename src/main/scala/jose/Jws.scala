package jose

import java.nio.charset.StandardCharsets
import java.security.NoSuchAlgorithmException
import java.util.Base64.{getUrlEncoder => encoder, getUrlDecoder => decoder}

import jose.Mapping.Mapper
import jose.Signer.SignerResolver

import scala.concurrent.Future
import scala.util.{Failure, Success, Try}

class UnverifiedJws(
                     val header: JwsHeader,
                     protected val payload: Array[Byte],
                     val signature: Array[Byte],
                     val compact: String
                   ) {

  def verify[T](key: Jwk, resolver: SignerResolver = Signer.defaultSignerResolver)(implicit mapper: Mapper[Array[Byte], T]): Try[VerifiedJws[T]] =
    resolver.tryGet(header.alg)
      .flatMap(_.tryVerify(key, payload, signature))
      .flatMap(mapper)
      .map(newPayload ⇒ new CompactedJws[T](
        header,
        newPayload,
        payload,
        signature,
        compact
      ))
}

trait VerifiedJws[T] {
  def header: JwsHeader
  def payload: T
  def rawPayload: Array[Byte]
  def signature: Array[Byte]

  def compact: String
}

private class LazyCompactingJws[T](
                                    val header: SerializedJwsHeader,
                                    val payload: T,
                                    val rawPayload: Array[Byte],
                                    val signature: Array[Byte]
                                  ) extends VerifiedJws[T] {
  lazy val compact = {
    def encode(bin: Array[Byte]) = encoder.encodeToString(bin)
    s"${encode(header.raw)}.${encode(rawPayload)}.${encode(signature)}"
  }
}

private class CompactedJws[T](
                               val header: JwsHeader,
                               val payload: T,
                               val rawPayload: Array[Byte],
                               val signature: Array[Byte],
                               val compact: String
                             ) extends VerifiedJws[T]

class UnsignedJws[T](
                      val header: JwsHeader,
                      val payload: T
                    ){
  def sign(key: Jwk, resolver: SignerResolver)(implicit mapper: Mapper[T, Array[Byte]]): Try[VerifiedJws[T]] =
    for {
      signer ← resolver.tryGet(header.alg)
      payloadBytes ← mapper(payload)
      serialHeader <- header.serialize
      sig ← signer.sign(
        key,
        s"${encoder.encodeToString(serialHeader.raw)}.${encoder.encodeToString(payloadBytes)}"
          .getBytes(StandardCharsets.US_ASCII)
      )
    } yield new LazyCompactingJws[T](serialHeader, payload, payloadBytes, sig)
}

object Jws {

  private implicit class TryHelpers[T](t: Try[T]) {
    def mapFailure(f: PartialFunction[Throwable, Throwable]) = t.transform (
      Success(_),
      e => Failure(if(f.isDefinedAt(e)) f(e) else e)
    )
  }

  def parse(compact: String): Try[UnverifiedJws] = {
    val split = compact.split('.')
    val triplet =
      if(split.length == 3)
        Try(
          (
            decoder.decode(split(0)),
            decoder.decode(split(1)),
            decoder.decode(split(2))
          )
        ).transform(Success(_), _ => Failure(new InvalidBase64))
      else Failure(new CompactNot3Parts)

    triplet.flatMap { case (rawHeader, payload, sig) =>
      JwsHeader.deserializer(rawHeader)
        .mapFailure { case e => new HeaderParsingError(e) }
        .map(header => new UnverifiedJws(header, payload, sig, compact))
    }
  }

  def sign[T](alg: String, key: Jwk, payload: T, resolver: SignerResolver = Signer.defaultSignerResolver)(implicit mapper: Mapper[T, Array[Byte]]): Try[VerifiedJws[T]] = {
    for {
      header <- UnserializedJwsHeader(alg).serialize
      signed <- new UnsignedJws[T](header, payload).sign(key, resolver)
    } yield signed
  }
}
