import io.iohk.atala.prism.kotlin.credentials.json.JsonBasedCredential
import io.iohk.atala.prism.kotlin.crypto.EC
import io.iohk.atala.prism.kotlin.crypto.keys.ECKeyPair
import io.iohk.atala.prism.kotlin.protos.PlainTextCredential
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.util.*

object EncoderKotlin {
    fun bytesTohex(bytes: ByteArray): String{
        return bytes.joinToString("") {  java.lang.String.format("%02x", it) }
    }

    fun listBytesTohex(bytes: List<Byte>): String{
        return bytes.joinToString("") {  java.lang.String.format("%02x", it) }
    }

    fun hexTobytes(hex: String): ByteArray {
        return hex.chunked(2)
                .map { it.toInt(16).toByte() }
                .toByteArray()
    }

    fun readFile(): PrismConnectionKotlin2.CreateDIDRes {
        val reader = BufferedReader(FileReader(File("./createDidRes.txt")))
        val comp1 = reader.readLine()
        val comp2 = reader.readLine()
        val encodedCredential = reader.readLine()
        val encodedMerkleProof = reader.readLine()
        val comp3 = PlainTextCredential(encodedCredential,encodedMerkleProof)
        val comp4 = JsonBasedCredential.fromString(reader.readLine())
        val comp5 = reader.readLine()
        val comp6 = reader.readLine()
        val comp7 = hexTobytes(reader.readLine())
        val privateKey = EC.toPrivateKey(hexTobytes(reader.readLine()).toList() )
        val comp8 = ECKeyPair(EC.toPublicKeyFromPrivateKey(privateKey),privateKey)
        reader.close()
        return PrismConnectionKotlin2.CreateDIDRes(comp1,comp2,comp3,comp4,comp5,comp6,comp7,comp8)
    }

    fun readFileMultiple(): MultipleCredentials.CreateDIDRes {
        val reader = BufferedReader(FileReader(File("./createDidRes.txt")))
        val sizeList = Integer.parseInt(reader.readLine())
        val messagesReceived: Array<MultipleCredentials.MesssagesReceived> = Array(sizeList,({i ->
            val comp1 = reader.readLine()
            val comp2 = reader.readLine()
            val encodedCredential = reader.readLine()
            val encodedMerkleProof = reader.readLine()
            val comp3 = PlainTextCredential(encodedCredential,encodedMerkleProof)
            val comp4 = JsonBasedCredential.fromString(reader.readLine())
            MultipleCredentials.MesssagesReceived(comp1,comp2,comp3,comp4)
        }))
        val comp2 = reader.readLine()
        val comp3 = reader.readLine()
        val comp4 = hexTobytes(reader.readLine())
        val privateKey = EC.toPrivateKey(hexTobytes(reader.readLine()).toList() )
        val comp5 = ECKeyPair(EC.toPublicKeyFromPrivateKey(privateKey),privateKey)
        reader.close()
        return MultipleCredentials.CreateDIDRes(messagesReceived.toList(),comp2,comp3,comp4,comp5)
    }
}