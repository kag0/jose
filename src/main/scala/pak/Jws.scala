package pak

import scala.concurrent.Future
import scala.util.{Failure, Success, Try}

import pak.Jwt.UnverifiedJwsExtensions

object Jws {
  trait Signer {
    def sign(key: Jwk, text: Array[Byte]): Try[Array[Byte]]
    def verify(key: Jwk, text: Array[Byte]): Option[Exception]
  }

  type Mapper[A, B] = A ⇒ Try[B]
  type SignerResolver = String ⇒ Option[Signer]

  implicit class SignerExt(resolver: SignerResolver) {
    def tryGet(alg: String) = resolver(alg)
      .map(signer ⇒ Success(signer))
      .getOrElse(Failure(new Exception("algorithm not found")))
  }

  case class Header(alg: String)

  class UnverifiedJws(
                       val header: Header,
                       protected val payload: Array[Byte],
                       val signature: Array[Byte],
                       val compact: String
                     ) {

    def verify[T](key: Jwk, resolver: SignerResolver)(implicit mapper: Mapper[Array[Byte], T]): Try[VerifiedJws[T]] =
      resolver.tryGet(header.alg)
        .flatMap(_.verify(key, payload).map(e ⇒ Failure(e)).getOrElse(Success(payload)))
        .flatMap(mapper(_))
        .map(newPayload ⇒ new CompactedJws[T](
          header,
          newPayload,
          payload,
          signature,
          compact
        ))
  }

  trait VerifiedJws[T] {
    def header: Header
    def payload: T
    def rawPayload: Array[Byte]
    def signature: Array[Byte]

    def compact: String
  }

  private class LazyCompactingJws[T](
                                      val header: Header,
                                      val payload: T,
                                      val rawPayload: Array[Byte],
                                      val signature: Array[Byte]
                                    ) extends VerifiedJws[T] {
    lazy val compact = ???
  }

  private class CompactedJws[T](
                                 val header: Header,
                                 val payload: T,
                                 val rawPayload: Array[Byte],
                                 val signature: Array[Byte],
                                 val compact: String
                               ) extends VerifiedJws[T]

  class UnsignedJws[T](
    val header: Header,
    val payload: T
  ){
    def sign(key: Jwk, resolver: SignerResolver)(implicit mapper: Mapper[T, Array[Byte]]): Try[VerifiedJws[T]] =
      for {
        signer ← resolver.tryGet(header.alg)
        text ← mapper(payload)
        sig ← signer.sign(key, text)
      } yield new LazyCompactingJws[T](header, payload, text, sig)
  }

  object blah {
    val parsed = Jws.parse("string")
    val verified = parsed.flatMap(_.verify[Object](null, null))

    val compacted = Jws.sign(null, "hi", null).map(_.compact)

    val v = for {
      parsed <- Jws.parse("")
      thing ← Future.successful(null)
      verified ← parsed.verifyJwt(null, null)
    } yield thing
  }

  def parse(compact: String): Try[UnverifiedJws] = ???

  def sign[T](key: Jwk, payload: T, resolver: SignerResolver)(implicit mapper: Mapper[T, Array[Byte]]): Try[VerifiedJws[T]] = {
    val header: Header = ???
    new UnsignedJws[T](header, payload).sign(key, resolver)
  }
}
