package jose

import java.security.{InvalidKeyException, NoSuchAlgorithmException, SignatureException}
import java.util
import javax.crypto.Mac

import jose.Signer.SignerResolver

import scala.util.{Failure, Success, Try}

trait Signer {
  def sign(key: Jwk, payload: Array[Byte]): Try[Array[Byte]]
  def verify(key: Jwk, payload: Array[Byte], signature: Array[Byte]): Option[Throwable]
  private[jose] def tryVerify(key: Jwk, payload: Array[Byte], signature: Array[Byte]): Try[Null] =
    verify(key, payload, signature).map(e => Failure(e)).getOrElse(Success(null))
  def resolver: SignerResolver
}

object Signer {
  type SignerResolver = PartialFunction[String, Signer]

  val defaultSignerResolver = HS256Signer.resolver

  implicit class SignerExt(resolver: SignerResolver) {
    def tryGet(alg: String) =
      if (resolver.isDefinedAt(alg))
        Success(resolver(alg))
      else
        Failure(new NoSuchAlgorithmException(s"Could not find signer for $alg"))
  }
}

object HS256Signer extends Signer {

  def sign(key: Jwk, payload: Array[Byte]) =
    for {
      validKey <- validateKey(key)
      sig <- Try {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(validKey.java)
        mac.doFinal(payload)
      }
    } yield sig

  def verify(key: Jwk, payload: Array[Byte], signature: Array[Byte]) = sign(key, payload) match {
    case Success(computedSig) =>
      if(util.Arrays.equals(signature, computedSig)) None
      else Some(new SignatureException("Signature doesn't match"))
    case Failure(e) => Some(e)
  }

  def validateKey(key: Jwk): Try[SecretKey] = key match {
    case secretKey: SecretKey if secretKey.k.length < 32 => Failure(new InvalidKeyException(s"Key too small, needed at least 256 bits, was ${secretKey.k.length *8}"))
    case k if k.alg.exists(alg => alg != "HS256") => Failure(new InvalidKeyException(s"Key is meant for use with ${k.alg.getOrElse("")}, needed HS256"))
    case secretKey: SecretKey => Success(secretKey)
    case _ => Failure(new InvalidKeyException(s"Needed a symmetric secret key 'oct', got ${key.kty}"))
  }

  val resolver = {
    case "HS256" => HS256Signer
  }
}
