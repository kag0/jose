package pak

import javax.crypto.spec.SecretKeySpec

trait Jwk

case class SecretKey(key: Array[Byte]) {
  val java: SecretKeySpec = ???
}
