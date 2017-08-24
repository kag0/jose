package jose

import java.nio.charset.StandardCharsets

import jose.Mapping.Mapper
import org.json4s.JsonDSL._
import org.json4s._
import org.json4s.native.JsonMethods._

import scala.util.{Success, Try}

sealed trait JoseHeader{
  def alg: String
}

sealed trait JwsHeader extends JoseHeader {
  def alg: String
  protected[jose] def serialize: Try[SerializedJwsHeader]
}

private[jose] case class SerializedJwsHeader(alg: String, raw: Array[Byte]) extends JwsHeader {
  val serialize = Success(this)
}

private[jose] case class UnserializedJwsHeader(alg: String) extends JwsHeader {
  lazy val serialize = JwsHeader.serializer(this).map(SerializedJwsHeader(alg, _))
}

object JwsHeader {
  val serializer: Mapper[JwsHeader, Array[Byte]] = header => Try {
    val json = "alg" -> header.alg
    compact(render(json)).getBytes(StandardCharsets.UTF_8)
  }
  def deserializer: Mapper[Array[Byte], JwsHeader] = ???
}

object JoseHeader {
  def mapper: Mapper[Array[Byte], JoseHeader] = ???
}