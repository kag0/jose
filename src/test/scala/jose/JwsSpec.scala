package jose

import java.nio.charset.StandardCharsets
import java.util.Base64

import jose.Mapping.Mapper

import scala.util.Success

object JwsSpec extends App {

  implicit val utf8Serializer: Mapper[String, Array[Byte]] = (s: String) => Success(s.getBytes(StandardCharsets.UTF_8))

  val jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"

  val key = SecretKey.random
  println(Base64.getEncoder.encodeToString(key.k))

  val jws = Jws.sign("HS256", key, "Hello world!").map(_.compact).get
  println(jws)

  /*
  val payload = for {
    unverified <- Jws.parse(jwt)
    verified <- unverified.verify[String](key)
  } yield verified.payload
  */

}
