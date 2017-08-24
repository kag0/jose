package jose

sealed trait Error extends Exception

class InvalidBase64 extends Error
class CompactNot3Parts extends Error
class HeaderParsingError(cause: Throwable) extends Error
class UnfamiliarAlgorithm extends Error
