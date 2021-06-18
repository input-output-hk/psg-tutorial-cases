import io.iohk.atala.prism.kotlin.credentials.BatchData
import io.iohk.atala.prism.kotlin.credentials.CredentialBatches
import io.iohk.atala.prism.kotlin.credentials.CredentialVerification
import io.iohk.atala.prism.kotlin.credentials.VerificationException
import io.iohk.atala.prism.kotlin.credentials.json.JsonBasedCredential
import io.iohk.atala.prism.kotlin.crypto.MerkleInclusionProof
import io.iohk.atala.prism.kotlin.crypto.SHA256Digest
import io.iohk.atala.prism.kotlin.extras.ProtoClientUtils
import io.iohk.atala.prism.kotlin.extras.findPublicKey
import io.iohk.atala.prism.kotlin.extras.toTimestampInfoModel
import io.iohk.atala.prism.kotlin.protos.*
import kotlinx.coroutines.runBlocking
import pbandk.decodeFromByteArray
import pbandk.encodeToByteArray

class ServicesKotlin(environment: String) {
    private val connector = ProtoClientUtils.connectorClient(environment, 50051)
    private val node = ProtoClientUtils.nodeClient(environment, 50053)
    fun createDID(name:String, operation:SignedAtalaOperation): RegisterDIDResponse{
        val registerDidRequest = RegisterDIDRequest(createDidOperation = operation, name = name)
        return  runBlocking { connector.RegisterDID(registerDidRequest) }
    }

    fun geneteConnectionToken(tokenCount:Int, did: String,requestNonce: ByteArray,signature:ByteArray): GenerateConnectionTokenResponse{
        val issuerGenerateConnectionTokenRequest = GenerateConnectionTokenRequest(count = tokenCount)
        return runBlocking{
            connector.GenerateConnectionTokenAuth(
                    issuerGenerateConnectionTokenRequest,
                    PrismMetadata(
                            did = did,
                            didKeyId = "master0", // NOTE: For now this is hardcoded as there are no other keys in the DIDs
                            didSignature = signature,
                            requestNonce = requestNonce
                    )
            )
        }
    }

    fun acceptsIssuerConnection(did:String,issuerConnectionToken:String,signature:ByteArray,requestNonce:ByteArray):ConnectionInfo{
        val holderAcceptsIssuerConnectionRequest = AddConnectionFromTokenRequest(token = issuerConnectionToken)
        return runBlocking {
            connector.AddConnectionFromTokenAuth(
                    holderAcceptsIssuerConnectionRequest,
                    PrismMetadata(
                            did = did,
                            didKeyId = "master0", // NOTE: For now this is hardcoded as there are no other keys in the DIDs
                            didSignature = signature,
                            requestNonce = requestNonce
                    )
            ).connection!!
        }
    }

    fun shareCredential(connectionId:String,did:String, signature:ByteArray, requestNonce:ByteArray, encodedCredential:String,encodedMerkleProof:String): SendMessageResponse{
        val credentialFromHolderMessage = AtalaMessage(
                message = AtalaMessage.Message.PlainCredential(
                        PlainTextCredential(
                                encodedCredential = encodedCredential,
                                encodedMerkleProof = encodedMerkleProof
                        )
                )
        )

        val holderSendMessageRequest = SendMessageRequest(
                connectionId,
                pbandk.ByteArr(credentialFromHolderMessage.encodeToByteArray())
        )
        return runBlocking {
            connector.SendMessageAuth(
                    holderSendMessageRequest,
                    PrismMetadata(
                            did = did,
                            didKeyId = "master0", // NOTE: For now this is hardcoded as there are no other keys in the DIDs
                            didSignature = signature,
                            requestNonce = requestNonce
                    )
            )
        }
    }

    fun receiveCredential(did:String,signature: ByteArray,requestNonce: ByteArray,limitRequests:Int,lastSeenMessageId:String = ""):List<PlainTextCredential>{
        var _lastSeenMessageId = lastSeenMessageId
        if(lastSeenMessageId.isEmpty()){
            _lastSeenMessageId = GetMessagesPaginatedRequest.defaultInstance.lastSeenMessageId
        }
        val verifierGetMessagesRequest = GetMessagesPaginatedRequest(limit = limitRequests,lastSeenMessageId=_lastSeenMessageId)
        val messages = runBlocking {
            connector.GetMessagesPaginatedAuth(
                    verifierGetMessagesRequest,
                    PrismMetadata(
                            did = did,
                            didKeyId = "master0", // NOTE: For now this is hardcoded as there are no other keys in the DIDs
                            didSignature = signature,
                            requestNonce = requestNonce
                    )
            ).messages
        }
        return messages.map{
            AtalaMessage.decodeFromByteArray(it.message.array).plainCredential!!
        }
    }

    fun verifyCredential(credential:PlainTextCredential): Boolean{
        val jsonCredential:JsonBasedCredential = JsonBasedCredential.fromString(credential.encodedCredential)
        val verifierReceivedCredentialIssuerDID = jsonCredential.content.getString("issuerDid")!!
        val verifierReceivedCredentialIssuanceKeyId = jsonCredential.content.getString("issuanceKeyId")!!
        val verifierReceivedCredentialIssuerDIDDocument = runBlocking {
            node.GetDidDocument(GetDidDocumentRequest(did = verifierReceivedCredentialIssuerDID)).document!!
        }

        val verifierReceivedCredentialIssuerKey = verifierReceivedCredentialIssuerDIDDocument.findPublicKey(verifierReceivedCredentialIssuanceKeyId)
        val verifierReceivedCredentialMerkleProof = MerkleInclusionProof.decode(credential.encodedMerkleProof)

        val verifierReceivedCredentialBatchId = CredentialBatches.computeCredentialBatchId(
                io.iohk.atala.prism.kotlin.identity.DID.fromString(verifierReceivedCredentialIssuerDID),
                verifierReceivedCredentialMerkleProof.derivedRoot()
        )

        val request = GetBatchStateRequest(batchId = SHA256Digest.fromHex(verifierReceivedCredentialBatchId.id).hexValue())
        val verifierReceivedCredentialBatchState = runBlocking {
            node.GetBatchState(request)
        }
        val verifierReceivedCredentialBatchData = BatchData(
                issuedOn = verifierReceivedCredentialBatchState.publicationLedgerData?.timestampInfo?.toTimestampInfoModel()!!,
                revokedOn = verifierReceivedCredentialBatchState.revocationLedgerData?.timestampInfo?.toTimestampInfoModel()
        )

        val credentialHashByte = jsonCredential.hash().value.map { it.toByte() }
        val verifierReceivedCredentialRevocationTime = runBlocking {
            node.GetCredentialRevocationTime(
                    GetCredentialRevocationTimeRequest(
                            batchId = SHA256Digest.fromHex(verifierReceivedCredentialBatchId.id).hexValue(),
                            credentialHash = pbandk.ByteArr(credentialHashByte.toByteArray())
                    )
            ).revocationLedgerData?.timestampInfo?.toTimestampInfoModel()
        }

        return try {
            CredentialVerification.verify(
                    keyData = verifierReceivedCredentialIssuerKey!!,
                    batchData = verifierReceivedCredentialBatchData,
                    credentialRevocationTime = verifierReceivedCredentialRevocationTime,
                    merkleRoot = verifierReceivedCredentialMerkleProof.derivedRoot(),
                    inclusionProof = verifierReceivedCredentialMerkleProof,
                    signedCredential = jsonCredential
            )
            true
        }catch (e: VerificationException){
            System.out.println("Credential verification fail: '$e'")
            false
        }
    }
}