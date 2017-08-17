package pak

import scala.util.Try

import pak.Jws.{SignerResolver, UnverifiedJws}



object Jwt {
  type Claims = ???

  implicit class UnverifiedJwsExtensions(jws: UnverifiedJws) {
    def verifyJwt(key: Jwk, resolver: SignerResolver): Try[Claims] = ???
  }
}
