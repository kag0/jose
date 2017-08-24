package jose

import java.security.spec.{RSAPrivateCrtKeySpec, RSAPrivateKeySpec, RSAPublicKeySpec}
import java.security._
import javax.crypto.spec.SecretKeySpec
import javax.crypto.{SecretKey => JSecretKey}

trait Jwk {
  def keyType = kty
  def kty: String
  // def use: Option[String]
  def alg: Option[String] = None
}

case class SecretKey(k: Array[Byte]) extends Jwk {
  val kty = "oct"
  val java = new SecretKeySpec(k, "jwk")
}

object SecretKey {
  def random = {
    val r = new SecureRandom
    val k = new Array[Byte](64)
    r.nextBytes(k)
    SecretKey(k)
  }
}

/*
trait RsaPublicKeyParams extends Jwk {
  val kty = "RSA"
  def n: BigInt // modulus
  def e: BigInt // exponent
  val javaPublicKey = {
    val keySpec = new RSAPublicKeySpec(n.bigInteger, e.bigInteger)
    val fact = KeyFactory.getInstance("RSA")
    fact.generatePublic(keySpec)
  }
}

case class RsaPublicKey(n: BigInt, e: BigInt) extends RsaPublicKeyParams

trait RsaPrivateKey extends RsaPublicKeyParams {
  def d: BigInt // private exponent
  def javaPrivateKey: PrivateKey
}

case class RsaCrtPrivateKey(
                             n: BigInt,
                             e: BigInt,
                             d: BigInt,
                             p: BigInt,
                             q: BigInt,
                             dp: BigInt,
                             dq: BigInt,
                             qi: BigInt
                           ) extends RsaPrivateKey {
  val javaPrivateKey = new RSAPrivateCrtKeySpec(
    n.bigInteger,
    e.bigInteger,
    d.bigInteger,
    p.bigInteger,
    q.bigInteger,
    dp.bigInteger,
    dq.bigInteger,
    qi.bigInteger
  )
}

*/