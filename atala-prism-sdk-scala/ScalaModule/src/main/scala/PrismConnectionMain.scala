import java.io.{BufferedWriter, File, FileWriter}
import java.util

import io.iohk.atala.prism.kotlin.credentials.json.JsonBasedCredential

import scala.util.Random

object PrismConnectionMain {

  def createDID(environment:String, nameRegistered:String): Unit ={
    val createDidRes = PrismConnectionKotlin2.INSTANCE.createDID(environment,nameRegistered)
    val writer = new BufferedWriter(new FileWriter(new File("./createDidRes.txt")))

    writer.write(createDidRes.component1())
    writer.newLine()
    writer.write(createDidRes.component2())
    writer.newLine()
    writer.write(createDidRes.component3().getEncodedCredential)
    writer.newLine()
    writer.write(createDidRes.component3().getEncodedMerkleProof)
    writer.newLine()
    writer.write(createDidRes.component4().getCanonicalForm)
    writer.newLine()
    writer.write(createDidRes.component5())
    writer.newLine()
    writer.write(createDidRes.component6())
    writer.newLine()
    writer.write(EncoderKotlin.INSTANCE.bytesTohex(createDidRes.component7()))
    writer.newLine()
    writer.write(EncoderKotlin.INSTANCE.listBytesTohex(createDidRes.component8().getPrivateKey.getEncoded))
    writer.close()
  }

  def createDIDMultiple(environment:String, nameDID:String, nameRegistered:java.util.List[String]): Unit ={
    val createDidRes = MultipleCredentials.INSTANCE.createDID(environment,nameDID,nameRegistered)
    val writer = new BufferedWriter(new FileWriter(new File("./createDidRes.txt")))

    writer.write(createDidRes.component1().size().toString)
    writer.newLine()
    createDidRes.component1().forEach(elem => {
      writer.write(elem.component1())
      writer.newLine()
      writer.write(elem.component2())
      writer.newLine()
      writer.write(elem.component3().getEncodedCredential)
      writer.newLine()
      writer.write(elem.component3().getEncodedMerkleProof)
      writer.newLine()
      writer.write(elem.component4().getCanonicalForm)
      writer.newLine()
    })
    writer.write(createDidRes.component2())
    writer.newLine()
    writer.write(createDidRes.component3())
    writer.newLine()
    writer.write(EncoderKotlin.INSTANCE.bytesTohex(createDidRes.component4()))
    writer.newLine()
    writer.write(EncoderKotlin.INSTANCE.listBytesTohex(createDidRes.component5().getPrivateKey.getEncoded))
    writer.close()
  }

  def main(args: Array[String]):Unit = {
    //val environment = "grpc-psg.atalaprism.io"
    val environment = "localhost"

    val nameRegistered = "A NAME"

    if (args.length > 0 && args(0).equals("CreateDID")) {
      if (args.length > 1) {
        val names = new util.LinkedList[String]()
        for (i <- 1 to Integer.parseInt(args(1))) {
          names.add(Random.nextString(20))
        }
        createDIDMultiple(environment, nameRegistered, names)
      } else {
        createDID(environment, nameRegistered)
      }
    } else if (args.length > 0 && args(0).equals("Verify")) {
      val file = EncoderKotlin.INSTANCE.readFile()
      PrismConnectionKotlin2.INSTANCE.verify(environment, file.component1(), file.component2(), file.component3(), file.component4())
    }else if(args.length > 0 && args(0).equals("VerifyMultiple")){
      val file = EncoderKotlin.INSTANCE.readFileMultiple()
      file.component1().forEach(x => {
        try {
          PrismConnectionKotlin2.INSTANCE.verify(environment, x.component1(), x.component2(), x.component3(), x.component4())
        }catch{
          case e: Throwable => {
            System.err.println("ERROR")
            System.err.println(e.getMessage)
          }
        }
      })
    }else if(args.length>0 && args(0).equals("Revoke")){
      val file = EncoderKotlin.INSTANCE.readFile()
      PrismConnectionKotlin2.INSTANCE.revoke(environment, file.getVerifierReceivedJsonCredential, file.component5(), file.component6(), file.component7(), file.component8())
    }else if(args.length>0 && args(0).equals("RevokeMultiple")){
      val file = EncoderKotlin.INSTANCE.readFileMultiple()
      val holderSignedCredentials = new util.LinkedList[JsonBasedCredential]()
      file.component1().forEach(x => holderSignedCredentials.add(x.getVerifierReceivedJsonCredential))
      MultipleCredentials.INSTANCE.revoke(environment, holderSignedCredentials,file.getBatchId, file.getIssueCredentialOperationByteArray, file.getIssuerMasterKeyPair)
    }else if(args.length>0 && args(0).equals("Complete")){
      PrismConnectionKotlin.INSTANCE.createDiD(environment,nameRegistered)
    } else{
      System.err.println("use command 'Complete', 'CreateDID', 'Verify', 'VerifyMultiple', 'Revoke', or 'RevokeMultiple'")
    }
  }
}
