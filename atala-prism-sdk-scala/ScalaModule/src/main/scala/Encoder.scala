import java.lang

object Encoder {
  def bytesTohex(bytes: Array[Byte]): String = bytes.map("%02x".format(_)).mkString

  def hexTobytes(hex: String): Array[Byte] = hex.sliding(2,2).toArray.map(Integer.parseInt(_, 16).toByte)

  def arrayToList(array: Array[Byte]): java.util.List[java.lang.Byte] = {
    val privateKeyList:java.util.List[java.lang.Byte] = new java.util.LinkedList[lang.Byte]()
    val it = array.iterator
    while(it.hasNext){
      privateKeyList.add(privateKeyList.size(),it.next())
    }
    privateKeyList
  }

  def listToArray(list: java.util.List[java.lang.Byte]): Array[Byte] = {
    val arrayEncoded = new Array[Byte](list.size())
    val it = list.iterator()
    var i:Int = 0
    while(it.hasNext){
      arrayEncoded.update(i,it.next())
      i += 1
    }
    arrayEncoded
  }
}
