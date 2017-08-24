package jose

import scala.util.Try

object Mapping {

  type Mapper[A, B] = A => Try[B]

}
