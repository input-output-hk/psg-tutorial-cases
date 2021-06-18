import io.iohk.atala.prism.kotlin.credentials.CredentialBatchId
import io.iohk.atala.prism.kotlin.credentials.CredentialBatches
import io.iohk.atala.prism.kotlin.credentials.content.CredentialContent
import io.iohk.atala.prism.kotlin.credentials.json.JsonBasedCredential
import io.iohk.atala.prism.kotlin.crypto.EC
import io.iohk.atala.prism.kotlin.crypto.SHA256Digest
import io.iohk.atala.prism.kotlin.crypto.keys.ECKeyPair
import io.iohk.atala.prism.kotlin.extras.*
import io.iohk.atala.prism.kotlin.identity.DID
import io.iohk.atala.prism.kotlin.protos.*

import kotlinx.coroutines.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import pbandk.decodeFromByteArray
import pbandk.encodeToByteArray

object MultipleCredentials {
    data class MesssagesReceived(val verifierReceivedCredentialIssuerDID: String,val verifierReceivedCredentialIssuanceKeyId: String,val verifierReceivedCredential: PlainTextCredential,val verifierReceivedJsonCredential: JsonBasedCredential)
    data class CreateDIDRes(val messagesReceived: List<MesssagesReceived>, val issuerDIDValue:String,val batchId:String,val issueCredentialOperationByteArray:ByteArray,val issuerMasterKeyPair:ECKeyPair)
    @kotlin.ExperimentalUnsignedTypes
    fun createDID(environment: String,nameDID:String, nameRegistered:List<String>): CreateDIDRes {
        val connector = ProtoClientUtils.connectorClient(environment, 50051)
        val node = ProtoClientUtils.nodeClient(environment, 50053)
        // the issuer registers its identity to the node
        val issuerMasterKeyPair = EC.generateKeyPair()
        val issuerCreateDIDOperation = ProtoUtils.createDidAtalaOperation(issuerMasterKeyPair)
        val issuerCreatedDIDSignedOperation = ProtoUtils.signedAtalaOperation(issuerMasterKeyPair, issuerCreateDIDOperation)

        println(issuerMasterKeyPair.privateKey.getD())

        // Usually the DID would be registered with the node, but, the connector can handle that as well
        // val issuerDIDSuffix = node.CreateDID(CreateDIDRequest(signedOperation)).id
        val registerDidRequest = RegisterDIDRequest(createDidOperation = issuerCreatedDIDSignedOperation, name = nameDID)
        val issuerRegisterDIDResponse = runBlocking { connector.RegisterDID(registerDidRequest) }

        val issuerDID = DID.fromString(issuerRegisterDIDResponse.did)

        // the DID takes some minutes to get confirmed by Cardano, in the mean time, the unpublished DID
        // can be used to authenticate requests to the backend
        val issuerUnpublishedDID = DID.createUnpublishedDID(issuerMasterKeyPair.publicKey)

        println(
                """
                Issuer DID registered, the transaction can take up to 10 minutes to be confirmed by the Cardano network
                - DID: ${issuerRegisterDIDResponse.did}
                - Cardano transaction id: ${issuerRegisterDIDResponse.transactionInfo?.transactionId}
                """.trimIndent()
        )

        val issuerGenerateConnectionTokenRequest = GenerateConnectionTokenRequest(count = 1)
        val issuerConnectionToken = runBlocking {
            connector.GenerateConnectionTokenAuth(
                    issuerGenerateConnectionTokenRequest,
                    RequestUtils.generateRequestMetadata(
                            issuerUnpublishedDID.value,
                            issuerMasterKeyPair.privateKey,
                            issuerGenerateConnectionTokenRequest
                    )
            ).tokens.first()
        }
        println("Issuer: Token for connecting with the holder generated = $issuerConnectionToken")

        val holderMasterKeyPair = EC.generateKeyPair()
        val holderUnpublishedDID = DID.createUnpublishedDID(holderMasterKeyPair.publicKey)
        println("Holder: First DID generated to connect with Issuer = $holderUnpublishedDID")

        val holderMasterKeyPair2 = EC.generateKeyPair()
        val holderUnpublishedDID2 = DID.createUnpublishedDID(holderMasterKeyPair2.publicKey)
        println("Holder: Second DID generated to connect with Verifier = $holderUnpublishedDID2")

        val issuerConnectionTokenDetails = runBlocking {
            connector.GetConnectionTokenInfo(GetConnectionTokenInfoRequest(token = issuerConnectionToken))
        }
        println(
                """
            Holder: Check Issuer's connection token details:
            - Issuer name = ${issuerConnectionTokenDetails.creatorName}
            - Issuer DID  = ${issuerConnectionTokenDetails.creatorDid}
            """.trimIndent()
        )

        val holderAcceptsIssuerConnectionRequest = AddConnectionFromTokenRequest(token = issuerConnectionToken)
        val holderIssuerConnection = runBlocking {
            connector.AddConnectionFromTokenAuth(
                    holderAcceptsIssuerConnectionRequest,
                    RequestUtils.generateRequestMetadata(
                            holderUnpublishedDID.value,
                            holderMasterKeyPair.privateKey,
                            holderAcceptsIssuerConnectionRequest
                    )
            ).connection!!
        }
        println("Holder (DID 1): Connected to Issuer, connectionId = ${holderIssuerConnection.connectionId}")

        val holderSignedCredentials  = nameRegistered.map {
            val holderCredentialContent = CredentialContent(
                    JsonObject(
                            mapOf(
                                    Pair("issuerDid", JsonPrimitive(issuerDID.value)),
                                    Pair("issuanceKeyId", JsonPrimitive("master0")),
                                    Pair(
                                            "credentialSubject",
                                            JsonObject(
                                                    mapOf(
                                                            Pair("name", JsonPrimitive(it)),
                                                            Pair("certificate", JsonPrimitive("Certificate of PRISM SDK tutorial completion"))
                                                    )
                                            )
                                    )
                            )
                    )
            )

            val holderUnsignedCredential = JsonBasedCredential(holderCredentialContent)
            val holderSignedCredential = holderUnsignedCredential.sign(issuerMasterKeyPair.privateKey)
            holderSignedCredential
        }
        val (holderCredentialMerkleRoot, holderCredentialMerkleProofs) = CredentialBatches.batch(holderSignedCredentials)
        val holderCredentialMerkleRootByte = holderCredentialMerkleRoot.hash.value.map { it.toByte() }
        val credentialBatchData = CredentialBatchData(
                issuerDid = issuerDID.suffix.value, // This requires the suffix only, as the node stores only suffixes
                merkleRoot = pbandk.ByteArr(holderCredentialMerkleRootByte.toByteArray())
        )
        val issueCredentialOperation = ProtoUtils.issueCredentialBatchOperation(credentialBatchData)


        val signedIssueCredentialOperation = ProtoUtils.signedAtalaOperation(issuerMasterKeyPair, issueCredentialOperation)
        val issuedCredentialResponse = runBlocking {
            node.IssueCredentialBatch(IssueCredentialBatchRequest(signedIssueCredentialOperation))
        }

        println(
                """
            Issuer: Credential issued to Holder, the transaction can take up to 10 minutes to be confirmed by the Cardano network
            - IssuerDID = $issuerDID
            - Cardano transaction id = ${issuedCredentialResponse.transactionInfo?.transactionId}
            - Batch id = ${issuedCredentialResponse.batchId}
            """.trimIndent()
        )

        // Issuer needs the connection id to send a message to Holder, which can be retrieved
        // from the token generated before.
        val issuerGetConnectionRequest = GetConnectionByTokenRequest(issuerConnectionToken)
        val issuerHolderConnectionId = runBlocking {
            connector.GetConnectionByTokenAuth(
                    issuerGetConnectionRequest,
                    RequestUtils.generateRequestMetadata(issuerUnpublishedDID.value, issuerMasterKeyPair.privateKey, issuerGetConnectionRequest)
            ).connection?.connectionId!!
        }


        // the connector allows any kind of message, this is just a way to send a credential but you can define your own

        val credentialsFromIssuerMessage = holderSignedCredentials.zip(holderCredentialMerkleProofs).map {
            MessageToSendByConnectionToken(connectionToken =  issuerConnectionToken, message=AtalaMessage(
                    message = AtalaMessage.Message.PlainCredential(
                            PlainTextCredential(
                                    encodedCredential = it.first.canonicalForm,
                                    encodedMerkleProof = it.second.encode()
                            )
                    )
            ))
        }

        val issuerSendMessageRequest = SendMessagesRequest(credentialsFromIssuerMessage)

        runBlocking {
            connector.SendMessagesAuth(
                    issuerSendMessageRequest,
                    RequestUtils.generateRequestMetadata(
                            issuerUnpublishedDID.value,
                            issuerMasterKeyPair.privateKey,
                            issuerSendMessageRequest
                    )
            )
        }
        println("Issuer: Credential sent to Holder")

        val holderGetMessagesRequest = GetMessagesPaginatedRequest(limit = nameRegistered.size)
        val holderReceivedMessages = runBlocking {
            connector.GetMessagesPaginatedAuth(
                    holderGetMessagesRequest,
                    RequestUtils.generateRequestMetadata(
                            holderUnpublishedDID.value,
                            holderMasterKeyPair.privateKey,
                            holderGetMessagesRequest
                    )
            ).messages
        }



        val verifierMasterKeyPair = EC.generateKeyPair()
        val verifierCreateDIDOperation = ProtoUtils.createDidAtalaOperation(verifierMasterKeyPair)
        val verifierCreateDIDSignedOperation = ProtoUtils.signedAtalaOperation(verifierMasterKeyPair, verifierCreateDIDOperation)

        val verifierRegisterDIDResponse = runBlocking {
            connector.RegisterDID(
                    RegisterDIDRequest(
                            createDidOperation = verifierCreateDIDSignedOperation,
                            name = "Verifier"
                    )
            )
        }
        val verifierDID = DID.fromString(verifierRegisterDIDResponse.did)
        val verifierUnpublishedDID = DID.createUnpublishedDID(verifierMasterKeyPair.publicKey)
        println(
                """
    Verifier DID registered, the transaction can take up to 10 minutes to be confirmed by the Cardano network
    - DID: $verifierDID
    - Cardano transaction id: ${verifierRegisterDIDResponse.transactionInfo?.transactionId}
    """.trimIndent()
        )
        println()

        // Verifier generates a token to connect with the credential subject
        val verifierGenerateConnectionTokenRequest = GenerateConnectionTokenRequest(count = 1)
        val verifierConnectionToken = runBlocking {
            connector.GenerateConnectionTokenAuth(
                    verifierGenerateConnectionTokenRequest,
                    RequestUtils.generateRequestMetadata(
                            verifierUnpublishedDID.value,
                            verifierMasterKeyPair.privateKey,
                            verifierGenerateConnectionTokenRequest
                    )
            ).tokens.first()
        }
        println("Verifier: Token for connecting with holder generated = $verifierConnectionToken")

        val holderAcceptsVerifierConnectionRequest = AddConnectionFromTokenRequest(token = verifierConnectionToken)
        val holderVerifierConnection = runBlocking {
            connector.AddConnectionFromTokenAuth(
                    holderAcceptsVerifierConnectionRequest,
                    RequestUtils.generateRequestMetadata(
                            holderUnpublishedDID2.value,
                            holderMasterKeyPair2.privateKey,
                            holderAcceptsVerifierConnectionRequest
                    )
            )
                    .connection!!
        }
        println("Holder (DID 2): Connected to Verifier, connectionId = ${holderVerifierConnection.connectionId}")

        holderReceivedMessages.map {
            val holderReceivedCredential = AtalaMessage
                    .decodeFromByteArray(it.message.array)
                    .plainCredential!!
            println(
                    """
                Holder: Message received
                - Canonical credential = ${holderReceivedCredential.encodedCredential}
                - Inclusion proof = ${holderReceivedCredential.encodedMerkleProof}
                """.trimIndent()
            )

            //SHARE CREDENTIAL
            val credentialFromHolderMessage = AtalaMessage(
                    message = AtalaMessage.Message.PlainCredential(
                            PlainTextCredential(
                                    encodedCredential = holderReceivedCredential.encodedCredential,
                                    encodedMerkleProof = holderReceivedCredential.encodedMerkleProof
                            )
                    )
            )

            val holderSendMessageRequest = SendMessageRequest(
                    holderVerifierConnection.connectionId,
                    pbandk.ByteArr(credentialFromHolderMessage.encodeToByteArray())
            )
            runBlocking {
                connector.SendMessageAuth(
                        holderSendMessageRequest,
                        RequestUtils.generateRequestMetadata(
                                holderUnpublishedDID2.value,
                                holderMasterKeyPair2.privateKey,
                                holderSendMessageRequest
                        )
                )
            }
        }
        println("Holder (DID 2): Credential sent to Verifier")


        val verifierGetMessagesRequest = GetMessagesPaginatedRequest(limit = nameRegistered.size)
        val verifierReceivedMessage = runBlocking {
            connector.GetMessagesPaginatedAuth(
                    verifierGetMessagesRequest,
                    RequestUtils.generateRequestMetadata(
                            verifierUnpublishedDID.value,
                            verifierMasterKeyPair.privateKey,
                            verifierGetMessagesRequest
                    )
            )
        }.messages

        val messagesReceived = verifierReceivedMessage.map {
            val verifierReceivedCredential = AtalaMessage
                    .decodeFromByteArray(it.message.array)
                    .plainCredential!!
            println("""
    Verifier: Message received
    - Canonical credential = ${verifierReceivedCredential.encodedCredential}
    - Inclusion proof = ${verifierReceivedCredential.encodedMerkleProof}
    """.trimIndent()
            )

            //Extract the credential data
            val verifierReceivedJsonCredential = JsonBasedCredential.fromString(verifierReceivedCredential.encodedCredential)
            val verifierReceivedCredentialIssuerDID = verifierReceivedJsonCredential.content.getString("issuerDid")!!
            val verifierReceivedCredentialIssuanceKeyId = verifierReceivedJsonCredential.content.getString("issuanceKeyId")!!
            println(
                    """
    Verifier: Received credential decoded
    - Credential: ${verifierReceivedJsonCredential.content}
    - Issuer DID: $verifierReceivedCredentialIssuerDID
    - Issuer issuance key id: $verifierReceivedCredentialIssuanceKeyId
    """.trimIndent()
            )
            MesssagesReceived(verifierReceivedCredentialIssuerDID,verifierReceivedCredentialIssuanceKeyId,verifierReceivedCredential,verifierReceivedJsonCredential)
        }
        return CreateDIDRes(messagesReceived,issuerDID.value,issuedCredentialResponse.batchId,issueCredentialOperation.encodeToByteArray(),issuerMasterKeyPair)
    }

    fun revoke(environment: String, holderSignedCredentials:List<JsonBasedCredential>, batchId:String,issueCredentialOperationByteArray:ByteArray,issuerMasterKeyPair:ECKeyPair) {
        val node = ProtoClientUtils.nodeClient(environment, 50053)

        val issuerRevokeCredentialOperation = ProtoUtils.revokeCredentialsOperation(
                batchOperationHash = SHA256Digest.compute(issueCredentialOperationByteArray.asList()),
                batchId = CredentialBatchId.fromString(batchId)!!,
                credentials = holderSignedCredentials
        )
        val issuerRevokeCredentialSignedOperation = ProtoUtils.signedAtalaOperation(issuerMasterKeyPair, issuerRevokeCredentialOperation)
        val issuerCredentialRevocationResponse = runBlocking {
            node.RevokeCredentials(
                    RevokeCredentialsRequest(issuerRevokeCredentialSignedOperation)
            )
        }
        println(
                """
    Issuer: Credential revoked, the transaction can take up to 10 minutes to be confirmed by the Cardano network
    - Cardano transaction id: ${issuerCredentialRevocationResponse.transactionInfo?.transactionId}
    """.trimIndent()
        )
    }
}