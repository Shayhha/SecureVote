from abc import ABC
import sys, socket, pickle, math, random, time, string, multiprocessing, pyodbc
from Crypto.Util.number import getPrime
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from PyQt5.QtCore import pyqtSignal, QThread, QRegExp
from PyQt5.QtGui import QRegExpValidator
from PyQt5.QtWidgets import QApplication, QDesktopWidget, QMainWindow
from PyQt5.uic import loadUi


#-----------------------------------------------------------ZKP-GRAPH-----------------------------------------------------------#
#class that represents ZKP graph isomorphism problem
class ZKP_Graph(ABC):

    # function that creates directed/undirected graph with n vertices and m edges
    @staticmethod
    def CreateGraph(n, m, isDirected=False):
        #check if m is greater than the maximum possible edges
        maxEdges = (n * (n - 1)) // 2 if not isDirected else n * (n - 1)  #max number of edges in a simple graph
        if m > maxEdges:
            raise ValueError(f'Error, invalid number of edges. A graph with {n} vertices can have at most {maxEdges} edges.')

        graph = {i: [] for i in range(1, n + 1)} #create a dict represented as vertexes as keys (numerical)
        edges = set() #create a set of edges 
        
        #iterate over in loop and add m edges to our graph
        while len(edges) < m:
            u = random.randint(1, n) #create random u vertex
            v = random.randint(1, n) #create random v vertex
            
            #check that u != v becasue we dont want loops in graph
            if u != v:
                if isDirected: #if true we add the edge as a directed edge
                    if (u, v) not in edges: #check that edge doesnt exists already
                        edges.add((u, v)) #add edge to edges set
                        graph[u].append(v) #add v to adjacency list of u
                else:  #else we add edge as undirected edge
                    if (u, v) not in edges and (v, u) not in edges: #check that edge doesnt exists already
                        edges.add((u, v)) #add edge to edges set
                        graph[u].append(v) #add v to adjacency list of u
                        graph[v].append(u) #add u to adjacency list of v

        return graph


    # function that creates isomorphic graph by permuting the vertices and mapping them to letters, returns premuted graph and permutation
    @staticmethod
    def CreatePermutedGraph(graph):
        vertices = list(graph.keys()) #create list of all vertices from graph
        random.shuffle(vertices) #shuffle vertices for random permutation

        #map each vertex to a unique character starting from letter "a"
        letters = list(string.ascii_lowercase[:len(vertices)]) #create list of characters 
        permutation = {vertices[i]: letters[i] for i in range(len(vertices))} #map each numerical vertex in graph to its unique letter
        
        #apply the mapping to create the permuted graph with letter labeled vertices
        permutedGraph = {permutation[vertex]: [] for vertex in vertices} #create new graph that holds our new mapped vertices
        for vertex in vertices: #iterate over graph dict and add its corresponding neighbors 
            permutedGraph[permutation[vertex]] = [permutation[neighbor] for neighbor in graph[vertex]] #add corresponding neighbors based on mapping
        
        return permutedGraph, permutation
    

    # method for initiating a connection with verifier (server) and starting verification, prover side (client)
    @staticmethod
    def StartVerification(clientSocket, secretKey, iv, port=4050, isAnswer=True):
        rounds = 10 #represnets number of rounds for verification
        decision = None #represents the decision of verifier for zkp test

        try:
            print(f'ZKP_Client: Starting ZKP Graph verification with verifier on port {port}.')

            # create our graph and permutation and send verifier its graph for verification
            graphProver = ZKP_Graph.CreateGraph(12,16) #create prover's graph (G)
            graphVerifier, permutation = ZKP_Graph.CreatePermutedGraph(graphProver) #create premuted graph (H) for verifier
            clientSocket.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(graphVerifier), secretKey, iv)) #send encrypted initial response with verifier's premuted graph (H)

            #iterate through 10 rounds with the verifier to prove that we know the secret permutation
            for _ in range(rounds):

                #get verifier's data and save the question with loads
                verifierData = clientSocket.recv(4096) #get initial binary data from verifier
                verifierQuestion = pickle.loads(DH_RSA.AES_Decrypt_CBC(verifierData, secretKey, iv)) #decrypt and save verifier's question
                verifierVertex = verifierQuestion[1] #save verifier's given vertex
                
                #verifiers question is tuple ([1,0], permutedVertex) and 1 means we answers correctly to previous answer, 0 if not
                if isAnswer: #if true we answer correctly with permutation dict
                    originalVertex = None #represnets original vertex coresponing with verifier's vertex

                    #iterate over permutation dict and find matching vertex
                    for vertex, permutedVertex in permutation.items():
                        if permutedVertex == verifierVertex: #if true we found the matching vertex to verifier's permuted vertex
                            originalVertex = vertex #save vertex for later use
                            break

                    #if we found the correct vertex we send it to verifier        
                    if originalVertex is not None:
                        permutedNeighbors = [permutation[neighbor] for neighbor in graphProver[originalVertex]] #create matching permuted neighbor list
                        clientSocket.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(permutedNeighbors), secretKey, iv)) #send encrypted result to verifier server
                        print('ZKP_Client: Answer sent to verifier!')

                else: #else we guess the adjacency list
                    numOfNeigbors = random.randint(0, len(graphProver)) #guess number from 0 to number of vertices in graph
                    guessedNeighbors = list(string.ascii_lowercase[:numOfNeigbors]) #create list of neighbors represented as letters
                    clientSocket.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(guessedNeighbors), secretKey, iv)) #send encryptd guess to verifier server 
                    print('ZKP_Client: Guess sent to verifier!')
            
            #get verifer's result at the end ([1,0] - last round result, resultPersentage)
            verifierResultData = clientSocket.recv(4096) #get final result from verifier
            verifierResult = pickle.loads(DH_RSA.AES_Decrypt_CBC(verifierResultData, secretKey, iv)) #decrypt and save the result

            #print result whether verifier is convinced that prover knowns the permutation
            if verifierResult[1] >= 0.9: #if he is convinced
                print(f'ZKP_Client: Verifer is convinced that prover knowns the permutation, prover answered {verifierResult[1] * 100}% correct.')
                decision = True
            else: #else prover failed to convince the verifier 
                print(f'ZKP_Client: Verifer is not convinced that prover knowns the permutation, prover answered {verifierResult[1] * 100}% correct.')
                decision = False
        except Exception as e:
            print(f'ZKP_Client: Error occurred: {e}') #print exception if occurred
        finally:
            return decision
    

    # method for initiating a connection with client (prover) and starting the test, verifier side (server)
    @staticmethod
    def StartVerifier(conn, secretKey, iv, port=4050):
        graphVerifier = None
        rounds = 10 #represnets number of rounds for verification
        answeredCorrectly = 0 #represents the number of correct answers from prover
        previousResult = 0 #represents previous result, 1 - prover was correct, 0 - prover was incorrect
        usedVertices = set() #represnets previously chosen vertices

        try:
            print(f'ZKP_Verifier: Starting ZKP Graph verification with client on port {port}.')

            #recive the verifier graph and save it for later use
            graphVerifierData = conn.recv(4096) #get initial binary data from client
            graphVerifier = pickle.loads(DH_RSA.AES_Decrypt_CBC(graphVerifierData, secretKey, iv)) #decrypt and save verifier's graph (H) given from prover
            if graphVerifier != None:
                print(graphVerifier)

            #iterate through 10 rounds with the client (prover) to check that he knows the secret permutation
            for _ in range(rounds):
                #select a random vertex that has not been chosen before
                vertices = list(graphVerifier.keys() - usedVertices) #exclude previously chosen vertices
                if not vertices: #if no remaining vertices, reset the usedVertices set
                    usedVertices.clear()
                    vertices = list(graphVerifier.keys())
                chosenVertex = random.choice(vertices) # choose a random vertex from vertices list
                usedVertices.add(chosenVertex) #mark the chosen vertex as used

                conn.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps((previousResult, chosenVertex)), secretKey, iv)) #send encrypted question to prover client

                proverAnswerData = conn.recv(4096) #get prover answer data from client
                proverAnswer = pickle.loads(DH_RSA.AES_Decrypt_CBC(proverAnswerData, secretKey, iv)) #decrypt and save provers answer from client

                if len(proverAnswer) == len(graphVerifier[chosenVertex]): #if same size we continue to check adjacency lists
                    sortedListVerifier = sorted(graphVerifier[chosenVertex]) #sort verifier list
                    sortedListProver = sorted(proverAnswer) #sort prover list
                    if sortedListProver == sortedListVerifier: #if true prover answer right
                        previousResult = 1 #indicate that previous round was correct
                        answeredCorrectly += 1 #add current answer to correct answer counter
                    else: #else lists do not match
                        previousResult = 0 #indicate that previous round was incorrect
                else: #else lists not in same length
                    previousResult = 0 #indicate that previous round was incorrect

            #encrypt and send last response to prover with its last result and total result in test
            conn.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps((previousResult, answeredCorrectly / rounds)), secretKey, iv))
            print(f'ZKP_Verifier: Sent result of verification to client.')
        except Exception as e:
            print(f'ZKP_Verifier: Error occurred: {e}') #print exception if occurred


    # method that returns permutation of graph
    def GetPermutation(permutation):
        output = 'Permutation function:\n'
        for original, permuted in permutation.items():
            output += f'{original} --> {permuted}\n'
        print(output) #print the permutation
        return output


#----------------------------------------------------------ZKP-GRAPH-END--------------------------------------------------------#

#-------------------------------------------------------------DH-RSA------------------------------------------------------------#
#class that represents Diffie-Hellman key exchange with RSA algorithm and digital signature for secure communication
class DH_RSA(ABC):
    
    # method to convert to number
    @staticmethod
    def ToNumber(message):
        # if message is string we encode it
        if isinstance(message, str):
            message = message.encode()
        return int.from_bytes(message, byteorder='big')


    # method to convert to bytes
    @staticmethod
    def ToByte(message):
        if isinstance(message, int):
            # convert and ensure a minimum of 1 byte to avoid issues with zero or small numbers
            return message.to_bytes((message.bit_length() + 7) // 8 or 1, 'big')
        elif isinstance(message, str):
            # convert the string to bytes using encode
            return message.encode()
        else:
            return message


    # method to convert to string
    @staticmethod
    def ToString(message):
        if isinstance(message, int):
            # convert and ensure a minimum of 1 byte to avoid issues with zero or small numbers
            return message.to_bytes((message.bit_length() + 7) // 8 or 1, 'big').decode()
        elif isinstance(message, bytes):
            # convert the bytes to string using decode
            return message.decode()
        else:
            return message


    # method to generate RSA public and private keys in specified length and e parameter for faster process
    @staticmethod
    def GetRSAKeys(rsaKeyLength=2048, e=65537):
        #represents our parameters for RSA algorithm
        publicKey, privateKey = None, None #represents our public and private keys 
        p, q, n, phi, e = None, None, None, None, None #represents parameters to calculate the keys

        #iterate in loop and try to generate two large distinct prime numbers
        while True:
            p, q = getPrime(rsaKeyLength), getPrime(rsaKeyLength) #generate the prime numbers with desired length
            if p != None and q != None and p != q: #means we generated different prime numbers, we break
                break
        
        #compute n and phi
        n = p * q #apply the formula for n
        phi = (p - 1) * (q - 1) #apply the formula for phi

        if e is None: #if true then we calcuate e for generating d
            while True:
                e = random.randint(2, phi - 1) #generate random e where 2 <= e <= phi-1
                if math.gcd(e, phi) == 1: #if true we found matching e that satisfy the co-prime feature of e and phi
                    break

        d = pow(e, -1, phi) #calcuate d such that (d * e) % phi = 1 (multiplicative inverse)

        publicKey = (n, e) #set the public key tuple
        privateKey = (n, d) #set the private key tuple

        return publicKey, privateKey
        

    # method to encrypt plaintext using RSA encryption 
    @staticmethod
    def RSA_Encrypt(plaintext, publicKey):
        n, e = publicKey #represents public key (n, e)
        
        #if true we received plaintext as string or bytes so we convert to number
        if isinstance(plaintext, str) or isinstance(plaintext, bytes):
            plaintext = DH_RSA.ToNumber(plaintext) #convert the plaintext to a number
        
        #encrypt the plaintext number using RSA formula: ciphertext = plaintext^e % n
        ciphertext = pow(plaintext, e, n)
        
        return ciphertext
    

    # method to decrypt plaintext using RSA decryption 
    @staticmethod
    def RSA_Decrypt(ciphertext, privateKey, toStr=False, toByte=False):
        n, d = privateKey #represents private key (n, d)

        #if true we received ciphertext as string or bytes so we convert to number
        if isinstance(ciphertext, str) or isinstance(ciphertext, bytes):
            ciphertext = DH_RSA.ToNumber(ciphertext) #convert the ciphertext to a number
        
        #decrypt the ciphertext using RSA formula: plaintext = ciphertext^d % n
        decipheredText = pow(ciphertext, d, n)
        
        # we check if we need to convert the decipheredText to string or bytes
        if toStr:
            decipheredText = DH_RSA.ToString(decipheredText) #convert the number back to string
        elif toByte:
            decipheredText = DH_RSA.ToByte(decipheredText) #convert the number back to bytes
        
        return decipheredText

    
    # method to encrypt plaintext using AES encryption in CBC mode
    @staticmethod
    def AES_Encrypt_CBC(plaintext, key, iv):
        # ensure plaintext is padded to be a multiple of the block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        paddedPlaintext = padder.update(plaintext) + padder.finalize()

        # create AES cipher in CBC mode with iv
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(paddedPlaintext) + encryptor.finalize()

        return ciphertext


    # method to decrypt ciphertext using AES decryption in CBC mode
    @staticmethod
    def AES_Decrypt_CBC(ciphertext, key, iv):
        # create AES cipher in CBC mode with iv
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        paddedPlaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(paddedPlaintext) + unpadder.finalize()

        return plaintext


    # method to create random byte array for our use in KDF and digital signatures
    @staticmethod
    def GetRandomBytes(length=16):
        return bytes(random.getrandbits(8) for _ in range(length))
    

    # method that returns sha-256 hash of given message
    @staticmethod
    def ToSHA256(message, toHex=False):
        if not isinstance(message, bytes): #ensure the message is byte array
            message = DH_RSA.ToByte(message) #convert to string and then to bytes to ensure its bytes
        digest = Hash(SHA256()) #create a SHA256 hash object
        digest.update(message) #update the hash object with the message bytes
        return digest.finalize() if not toHex else digest.finalize().hex() #return sha-256 hash of message


    # method that creates digital signature from given message and rsa private key
    @staticmethod
    def CreateSignature(message, privateKey):
        messageHash = DH_RSA.ToSHA256(message) #create sha-256 hash of our message
        signature = DH_RSA.RSA_Encrypt(messageHash, privateKey) #enrypt message hash with private key and create signature
        # print(message.hex())
        # print(messageHash.hex())
        return signature #return signature


    # method that verifies given signature using rsa public key
    @staticmethod
    def VerifySignature(message, signature, publicKey):
        messageHash = DH_RSA.RSA_Decrypt(signature, publicKey) #decrypt signature and retrive message hash using public key
        if not isinstance(messageHash, bytes): #ensure that message hash is bytes
            messageHash = DH_RSA.ToByte(messageHash) #convert message hash to bytes with our method
        # print(message.hex())
        # print(messageHash.hex())
        return DH_RSA.ToSHA256(message) == messageHash #return if signature hash matches our message hash
    

    # method that creates AES key used KDF with diffie hellman shared secret
    @staticmethod
    def GetAESKey(value, salt, keyLength=128):
        #convert the shared secret to bytes
        if isinstance(value, int):
            value = DH_RSA.ToByte(value)

        #convert the salt to bytes
        if isinstance(salt, int):
            salt = DH_RSA.ToByte(salt)

        #check if key length is valid, if not throw exception
        if keyLength != 128 and keyLength != 192 and keyLength != 256:
            raise ValueError('Error, AES key length is invalid')

        #derive the AES key using HKDF using shared secret
        kdf = HKDF(
            algorithm=SHA256(),
            length=keyLength//8,
            salt=salt,
            info=None 
        )
        aesKey = kdf.derive(value)
        return aesKey


    # method that represents client side in secure diffe hellman key exchange and authenticating server with rsa
    @staticmethod
    def DH_Client(clientSocket, primeLength=2048, port=4050):
        try:
            print(f'DH_Client: Starting secure connection with DH_Server on port {port}.')

            #initial parameters both parties will use for DH key exchange
            p = getPrime(primeLength) #represents the prime number both parties will use
            alpha = random.randint(2, p - 2) #represents the chosen alpha parameter for key exchange

            #!create client public and private keys for RSA
            clientPublicKey, clientPrivateKey = DH_RSA.GetRSAKeys()

            #!receive the server's rsa public key and initate secure diffie hellman key exchange
            serverPublicKeyData = clientSocket.recv(4096) #get initial binary data from server with our rsa public key
            serverPublicKey = pickle.loads(serverPublicKeyData) #save our server public key we received for later use

            #!send client public key to server for secure diffie hellman key exchange
            clientSocket.sendall(pickle.dumps(clientPublicKey)) 

            #!send client digital signature to server for mutual authentication
            clientMessage = DH_RSA.GetRandomBytes() #create message for client signature
            clientSignature = DH_RSA.CreateSignature(clientMessage, clientPrivateKey) #create signature using client private key
            clientSocket.sendall(pickle.dumps((clientMessage, clientSignature))) #send client message and signature to server

            #!receive server's signature and verify its authenticity
            serverSignatureData = clientSocket.recv(4096) #get server signature data
            serverMessage, serverSignature = pickle.loads(serverSignatureData) #get server message and signature
            if not DH_RSA.VerifySignature(serverMessage, serverSignature, serverPublicKey): #check if authentication failed
                raise RuntimeError('DH_Client: Digital signature verification failed with server!\n')
            else: #else we print successful authentication
                print('DH_Client: Digital signature verification successful with server!\n')

            #we choose our "a" secret parameter and calculate "A" public parameter for first party
            a = random.randint(1, p - 1) #represents the chosen "a" seccret parameter 
            A = pow(alpha, a, p) #calculate public key to send to second party with formula: alpha^a % p

            #encrypt our dh parameters with server public key and send them to server
            encryptedParams = (DH_RSA.RSA_Encrypt(p, serverPublicKey), DH_RSA.RSA_Encrypt(alpha, serverPublicKey), DH_RSA.RSA_Encrypt(A, serverPublicKey))
            clientSocket.sendall(pickle.dumps(encryptedParams)) 

            #receive the server's B parameter, secret salt, iv and calcuate our shared secret
            dhParamData = clientSocket.recv(4096) #get binary data from server with his B parameter and secret salt
            B, secretSalt, iv = pickle.loads(dhParamData) #save B parameter for calculation of secret
            B, secretSalt, iv = DH_RSA.RSA_Decrypt(B, clientPrivateKey), DH_RSA.RSA_Decrypt(secretSalt, clientPrivateKey, toByte=True), DH_RSA.RSA_Decrypt(iv, clientPrivateKey, toByte=True) #decrypt the parameters using client public key

            #calculate the shared secret and generate aes key with salt
            S = pow(B, a, p) #calculate shared secret
            secretKey = DH_RSA.GetAESKey(S, secretSalt) #create aes key with kdf and secret salt
            print(f'DH_Client: AES key: {secretKey.hex()} IV: {iv.hex()}\n') #print aes key and iv of client

            #finally we return socket, aes key and iv for communicating with center
            return clientSocket, secretKey, iv

        except Exception as e:
            print(f'DH_Client: Error occurred: {e}') #print exception if occurred


    # method that represents server side in secure diffe hellman key exchange and authenticating client with rsa
    @staticmethod
    def DH_Server(conn, port=4050):
        try:
            print(f'DH_Server: Connection established with DH_Client on port {port}.\n')

            #!create server public and private keys for RSA 
            serverPublicKey, serverPrivateKey = DH_RSA.GetRSAKeys()
            
            #!send server public key to client for secure diffie hellman key exchange
            conn.sendall(pickle.dumps(serverPublicKey)) 

            #!receive the client's rsa public key and initate secure diffie hellman key exchange
            clientPublicKeyData = conn.recv(4096) #get initial binary data from client with our rsa public key
            clientPublicKey = pickle.loads(clientPublicKeyData) #save our public key we received for later use

            #!receive client's signature and verify its authenticity
            clientSignatureData = conn.recv(4096) #get client signature data
            clientMessage, clientSignature = pickle.loads(clientSignatureData) #get client message and signature
            if not DH_RSA.VerifySignature(clientMessage, clientSignature, clientPublicKey): #check if authentication failed
                raise RuntimeError('DH_Server: Digital signature verification failed with client!\n')
            else: #else we print successful authentication
                print('DH_Server: Digital signature verification successful with client!\n')
            
            #!send server digital signature to client for mutual authentication
            serverMessage = DH_RSA.GetRandomBytes() #create message for server signature
            serverSignature = DH_RSA.CreateSignature(serverMessage, serverPrivateKey) #create signature using server private key
            conn.sendall(pickle.dumps((serverMessage, serverSignature))) #send message and signature to client
            
            #receive p, alpha and A parametrs from client to calculate our parameters
            dhParametersData = conn.recv(4096) #get initial binary data from client of diffie hellman parameters p and alpha
            p, alpha, A = pickle.loads(dhParametersData) #save diffie hellman parameters we got from client

            #decrypt dh parameters we received from client using server private key
            p, alpha, A = DH_RSA.RSA_Decrypt(p, serverPrivateKey), DH_RSA.RSA_Decrypt(alpha, serverPrivateKey), DH_RSA.RSA_Decrypt(A, serverPrivateKey)

            #we choose our "b" secret parameter and calculate "B" public parameter for first party
            b = random.randint(1, p - 1) #represents the chosen "b" secret parameter 
            B = pow(alpha, b, p) #calculate public key to send to second party with formula: alpha^a % p

            #finally send B parameter with shared KDF salt and iv to client to establish shared secret
            secretSalt = DH_RSA.GetRandomBytes() #retrive a 16 byte salt for KDF function
            iv = DH_RSA.GetRandomBytes() #retrive a 16 byte initialization vector for AES CBC algorithm
            encryptedParam = (DH_RSA.RSA_Encrypt(B, clientPublicKey), DH_RSA.RSA_Encrypt(secretSalt, clientPublicKey), DH_RSA.RSA_Encrypt(iv, clientPublicKey)) #encrypt parameters 
            conn.sendall(pickle.dumps(encryptedParam))

            #calculate the shared secret and generate aes key with salt 
            S = pow(A, b, p) #calculate shared secret
            secretKey = DH_RSA.GetAESKey(S, secretSalt) #create aes key with KDF and secret salt
            print(f'DH_Server: AES key: {secretKey.hex()} IV: {iv.hex()}\n') #print aes key and iv of server

            #finally we return conn, aes key and iv for communicating with client
            return conn, secretKey, iv

        except Exception as e:
            print(f'DH_Server: Error occurred: {e}') #print exception if occurred

#-----------------------------------------------------------DH-RSA-END----------------------------------------------------------#

#-----------------------------------------------------------SQL-HELPER----------------------------------------------------------#
# class for SQL queries to our SecureVote database
class SQLHelper(ABC):

    # method for getting a connection for SecureVote sql database
    @staticmethod
    def GetDBConnection():
        # using windows authentication (no username/password)
        connectionString = (
            'DRIVER={ODBC Driver 17 for SQL Server};'
            'SERVER=localhost;'          #server name
            'DATABASE=SecureVote;'       #database name
            'Trusted_Connection=yes;'    #use Windows authentication
        )
        conn = pyodbc.connect(connectionString)
        return conn
    

    # method for getting voter information from database
    @staticmethod
    def GetVoterInfo(conn, voterId):
        cursor = conn.cursor()
        try:
            query = '''
                SELECT firstName, lastName, address, city, state 
                FROM Voters 
                WHERE voterId = ?
            '''
            cursor.execute(query, (voterId,))
            result = cursor.fetchone()
            
            # check if result is none, then print an error
            if result is None:
                print(f'No voter found with voterId {voterId}.')
                return None  
            
            # return voter information as a dictionary
            voterInfo = {
                'firstName': result[0], 'lastName': result[1],
                'address': result[2], 'city': result[3], 'state': result[4]
                }
            return voterInfo
        except Exception as e:
            print(f'Error fetching voter info: {e}')
            return None
        finally:
            cursor.close()


    # method for if checking voter password matches in database 
    @staticmethod
    def AuthVoter(conn, voterId, password):
        cursor = conn.cursor()
        try:
            query = '''
                SELECT COUNT(*) FROM Voters WHERE voterId = ? AND password = ?
            '''
            cursor.execute(query, (voterId, password,))
            result = cursor.fetchone()
            
            # if found one entry it means we found voter
            if result and result[0] == 1:
                print(f'Voter authenticated with voterId {voterId}.')
                return True
            # else we didnt find our voter
            else:
                print(f'Voter authentication failed with voterId {voterId}.')
                return False

        except Exception as e:
            print(f'Error authenticating voter in databse: {e}')
            return False
        finally:
            cursor.close()


    # method for checking voter status in database (1 for voted, else 0)
    @staticmethod
    def CheckVoterStatus(conn, voterId):
        cursor = conn.cursor()
        try:
            query = '''
                SELECT isVoted FROM Votes WHERE voterId = ?
            '''
            cursor.execute(query, (voterId,))
            result = cursor.fetchone()
            
            # if found no voter with matching voter id we return -1
            if result is None:
                print(f'No voter found with voterId {voterId}.')
                return -1
            
            # save vote status and return it for later proccessing
            isVoted = result[0]
            return isVoted 
        except Exception as e:
            print(f'Error checking voting status: {e}')
            return False
        finally:
            cursor.close()


    # method for checking all voters status in database, for determine how many votes remain
    @staticmethod
    def CheckAllVotersStatus(conn):
        cursor = conn.cursor()
        try:
            query = '''
                SELECT COUNT(*) FROM Votes WHERE isVoted = 0
            '''
            cursor.execute(query)
            result = cursor.fetchone()
            
            # get the count of voters who haven't voted
            notVotedCount = result[0] if result else 0
            
            # if we received 0 from count it means all voters voted
            if notVotedCount == 0:
                print('All voters have voted.')
            else:
                print(f'{notVotedCount} voters have not voted.')
            
            return notVotedCount #return number of not voted
        except Exception as e:
            print(f'Error checking voter statuses: {e}')
            return -1 #return -1 in case of an error
        finally:
            cursor.close()


    #method for setting voter status in database (1 for voted, else 0)
    @staticmethod
    def SetVoterStatus(conn, voterId=-1, status=1, reset=False):
        cursor = conn.cursor()
        try:
            # if true it means we reset all voters back to 0 (not voted)
            if reset and voterId == -1:
                query = '''
                    UPDATE Votes SET isVoted = 0
                '''
                cursor.execute(query)
                print('All voters have been reset to not voted (isVoted = 0).')
            # else we update the status of a specific voter
            else:
                query = '''
                    UPDATE Votes SET isVoted = ? WHERE voterId = ?
                '''
                cursor.execute(query, (status, voterId))
                print(f'Vote status for voterId {voterId} updated to {status}.')
            
            conn.commit()
            return True
        except Exception as e:
            print(f'Error updating voter status: {e}')
            return False
        finally:
            cursor.close()


    # method for updating results of center in database and also for reset
    @staticmethod
    def UpdateResults(conn, centerId=-1, demInc=0, repInc=0, reset=False):
        cursor = conn.cursor()
        try:
            # if true it means we want to reset all center results back to 0
            if reset and centerId == -1:
                query = '''
                    UPDATE Results SET democratVotes = 0, republicanVotes = 0
                '''
                cursor.execute(query)
                print('All ccenter results have been reset to 0.')
            # else we need to increment the result of specific center
            elif not reset and centerId != -1:
                query = '''
                    UPDATE Results 
                    SET democratVotes = democratVotes + ?, 
                        republicanVotes = republicanVotes + ? 
                    WHERE centerId = ?
                '''
                cursor.execute(query, (demInc, repInc, centerId))
                print(f'Results updated for centerId {centerId}.')
            # else we had an issue with arguments
            else:
                raise ValueError('Invalid parameters: please provide valid argumenst for UpdateResults method.')
            
            conn.commit()
            return True
        except Exception as e:
            print(f'Error updating results: {e}')
            return False
        finally:
            cursor.close()


    # method for calculating results from all centers in database and return final result
    @staticmethod
    def GetTotalResults(conn):
        cursor = conn.cursor()
        try:
            query = '''
                SELECT SUM(democratVotes) AS totalDemVotes, SUM(republicanVotes) AS totalRepVotes
                FROM Results
            '''
            cursor.execute(query)
            result = cursor.fetchone() 
            
            # save results from database
            totalDemVotes = result[0] if result[0] is not None else 0
            totalRepVotes = result[1] if result[1] is not None else 0

            print(f'Total DemResults: {totalDemVotes}, Total RepResults: {totalRepVotes}')
            return totalDemVotes, totalRepVotes #return results in tuple 
        except Exception as e:
            print(f'Error calculating total results: {e}')
            return None #return none in case of an error
        finally:
            cursor.close()


    # method for adding voter to database
    @staticmethod
    def AddVoter(conn, voterId, password, firstName, lastName, address, city, state):
        cursor = conn.cursor()
        try:
            # first we check if the voterId already exists in the database
            checkQuery = '''
                SELECT COUNT(*) FROM Voters WHERE voterId = ?
            '''
            cursor.execute(checkQuery, (voterId,))
            result = cursor.fetchone()

            # if we found a voter registered with that id it means the voterId already exists
            if result[0] > 0:
                print(f'Voter with voterId {voterId} already exists.')
                return 0
            
            # secondly we insert the new voter data into the Voters table
            voterQuery = '''
                INSERT INTO Voters (voterId, password, firstName, lastName, address, city, state)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            '''
            cursor.execute(voterQuery, (voterId, password, firstName, lastName, address, city, state,))
            
            # thirdly we add the voter to the Votes table with a default value for 'isVoted' as 0
            voteQuery = '''
                INSERT INTO Votes (voterId, isVoted)
                VALUES (?, 0)
            '''
            cursor.execute(voteQuery, (voterId,))
            
            # commit the transaction to save both changes (Voters and Votes)
            conn.commit()
            
            print(f'Voter {voterId} successfully added to both Voters and Votes tables.')
            return 1

        except Exception as e:
            # ff an error occurs, print the error and rollback any changes
            print(f'Error adding voter: {e}')
            conn.rollback()
            return -1

        finally:
            cursor.close()

#---------------------------------------------------------SQL-HELPER-END--------------------------------------------------------#

#------------------------------------------------------------VERIFIER-----------------------------------------------------------#
# class that represents verifier server that authenticates users with zkp graph isomorphism
class Verifier(ABC):

    # method for initializing verifier server with secure connection using Diffie-Hellman and RSA
    @staticmethod
    def InitVerifier(port=9000):
        try:
            #create new process for verifier server to try and initiate connection for key exchange
            serverProcess = multiprocessing.Process(target=Verifier.ProcessVerifier, args=(port,))
            serverProcess.daemon = True #makes server exit when main process exits
            serverProcess.start() #start server process
            time.sleep(1)

            #create client socket and try to connect to server
            clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create cilent socket
            clientSocket.connect(('localhost', port)) #try to connect to server on desired port

            #call our secure Diffie-Hellman key exchange to create secure connection with server
            clientSocket, secretKey, iv = DH_RSA.DH_Client(clientSocket, port=port)

            #finally return socket, aes key and iv for communicating with verifier
            return clientSocket, secretKey, iv

        except Exception as e:
            clientSocket.close() #close connection if exeption occurred
            print(f'Init verifier: Error occurred: {e}') #print exception if occurred


    # method that represents verifier server for processing ZKP graph isomorphism verifications
    @staticmethod
    def ProcessVerifier(port=9000):
        try:
            #create server socket
            serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create server socket
            serverSocket.bind(('localhost', port)) #bind socket to desired port
            serverSocket.listen(1) #listen for coming connection from client (prover)
            print(f'ZKP_Server: Verifier server listening on port {port}...')

            #wait for incoming connections
            conn, addr = serverSocket.accept() #accpet connection when received 
            print(f'ZKP_Server: Connection established with client at {addr}.')

            #call our secure Diffie-Hellman key exchange to create secure connection with client
            conn, secretKey, iv = DH_RSA.DH_Server(conn, port=port)

            # loop to handle incoming messages from application
            while True:
                #receive inital bytes from connection
                data = conn.recv(4096)

                # decrypt given message and process it later
                message = pickle.loads(DH_RSA.AES_Decrypt_CBC(data, secretKey, iv))

                # if true we received a valid message from application
                if isinstance(message, tuple) and len(message) == 2:
                    # if true we received message to start zkp verification
                    if message[0] == True and message[1] == 'Verify':
                        ZKP_Graph.StartVerifier(conn, secretKey, iv, port) #call verifier to verifiy client
                    # else it means we recevied a request to finish verifier process
                    elif message[0] == False and message[1] == 'Exit':
                        print(f'ZKP_Server: Exit command received. Shutting down server...')
                        break

                # else we recevied unknown message, we notify about it
                else:
                    print(f'ZKP_Server: Unknown message received: {message}')
                    
        except Exception as e:
            print(f'ZKP_Server: Error occurred: {e}') #print exception if occurred
        finally:
            conn.close() #close connection
            serverSocket.close() #close socket
            print(f'ZKP_Server: Verifier on port {port} Exited.')

#----------------------------------------------------------VERIFER-END----------------------------------------------------------#

#------------------------------------------------------------CENTER-------------------------------------------------------------#
# class that represents voting centers that perfrom the tallying
class Center(ABC):

    # method for initializing voting center with secure connection using Diffie-Hellman and RSA
    @staticmethod
    def InitCenter(centerId, port=4050):
        try:
            #create new process for ceenter server to try and initiate connection for key exchange
            serverProcess = multiprocessing.Process(target=Center.ProccessCenter, args=(centerId, port,))
            serverProcess.daemon = True #makes server exit when main process exits
            serverProcess.start() #start server process
            time.sleep(1)

            #create client socket and try to connect to server
            clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create cilent socket
            clientSocket.connect(('localhost', port)) #try to connect to server on desired port

            #call our secure Diffie-Hellman key exchange to create secure connection with server
            clientSocket, secretKey, iv = DH_RSA.DH_Client(clientSocket, port=port)

            #finally return socket, aes key and iv for communicating with center
            return clientSocket, secretKey, iv

        except Exception as e:
            clientSocket.close() #close connection if exeption occurred
            print(f'Init Center {centerId}: Error occurred: {e}') #print exception if occurred


    # method that represents center server for processing votes securly
    @staticmethod
    def ProccessCenter(centerId, port=4050):
        try:
            #create server socket for center
            serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create server socket
            serverSocket.bind(('localhost', port)) #bind socket to desired port
            serverSocket.listen(1) #listen for coming connection from client
            print(f'Center {centerId}: Center listening on port {port}...')

            #wait for incoming connections
            conn, addr = serverSocket.accept() #accpet connection when received
            print(f'Center {centerId}: Connection established with client at {addr}.')

            #call our secure Diffie-Hellman key exchange to create secure connection with client
            conn, secretKey, iv = DH_RSA.DH_Server(conn, port=port)

            #create database connection for center
            dbConn = SQLHelper.GetDBConnection()

            # loop to handle incoming messages from application
            while True:
                #receive inital bytes from connection
                data = conn.recv(4096)

                # decrypt given message and process it later
                message = pickle.loads(DH_RSA.AES_Decrypt_CBC(data, secretKey, iv))

                # if true we received a valid message from application
                if isinstance(message, tuple) and len(message) == 2:
                    # if true it means we recevied a vote to process
                    if message[0] == True:
                        # received democrat vote, we increment the democrat counter
                        if message[1] == 'Democrat':
                            if SQLHelper.UpdateResults(dbConn, centerId, demInc=1):
                                conn.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(True), secretKey, iv)) #we send true to confirm the tally
                            else:
                                conn.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(False), secretKey, iv)) #else we send false to notify for failuire
                        # received republican vote, we increment the republican counter
                        elif message[1] == 'Republican':
                            if SQLHelper.UpdateResults(dbConn, centerId, repInc=1):
                                conn.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(True), secretKey, iv)) #we send true to confirm the tally
                            else:
                                conn.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(False), secretKey, iv)) #else we send false to notify for failuire

                    # else it means we recevied a request to finish center process
                    elif message[0] == False and message[1] == 'Exit':
                        print(f'Center {centerId}: Exit command received. Shutting down server...')
                        break
                # else we recevied unknown message, we notify about it
                else:
                    print(f'Center {centerId}: Unknown message received: {message}')
            
        except Exception as e:
            print(f'Center {centerId}: Error occurred: {e}') #print exception if occurred
        finally:
            conn.close() #close connection
            serverSocket.close() #close socket
            dbConn.close() #close db connection
            print(f'Center {centerId}: Center on port {port} Exited.')

#----------------------------------------------------------CENTER-END-----------------------------------------------------------#

#----------------------------------------------------------SECURE-VOTE----------------------------------------------------------#
# class that represents main app of secure voting system
class SecureVote(QMainWindow):
    verifier = None #represents verifier with (verifierSocket, verifierAesKey, verifierIv) tuple
    centersList = [] #represents centers list with (centerSocket, centerAesKey, centerIv) tuples
    dbConn = None #represents our database connection
    voterId = None #represents voter id

    def __init__(self):
        super(SecureVote, self).__init__()
        loadUi('SecureVote.ui', self) #load the ui file
        self.initUI() #call init method
        self.initDBConnection() #call init db method
        
    
    # method to initialize GUI methods and events
    def initUI(self):
        self.setWindowTitle('SecureVote') #set title of window
        self.CancelButton.clicked.connect(self.ShowMainWindow)
        self.SubmitButton.clicked.connect(self.AddVoterToApp)
        self.addVoterButton.clicked.connect(self.ShowVoterSubmit)
        self.verifyButton.clicked.connect(self.VerifyVoter)
        self.demButton.clicked.connect(lambda: self.ProcessVote('Democrat'))
        self.repButton.clicked.connect(lambda: self.ProcessVote('Republican'))
        self.initValidators()
        self.UpdateCounterLabel('0')
        self.UpdateIdPass('', '')
        self.UpdateInfoLabel('')
        self.UpdateVoterInfo('', '', '', '')
        self.UpdateSubmitInfo('', '', '', '', '', '', '')
        self.UpdateSubmitInfoLabel('')
        self.ToggleVerificationUI(False)
        self.ToggleVoterUI(False)
        self.center() #make the app open in center of screen
        self.show() #show the application
        # start the processes initialization in a thread
        self.initProcessesThread = Init_Processes_Thread(self)
        # connect relevant signals for thread
        self.initProcessesThread.updateInfoLabelSignal.connect(self.UpdateInfoLabel)
        self.initProcessesThread.updateVerificationUISignal.connect(self.ToggleVerificationUI)
        self.initProcessesThread.start() #start init processes thread


    # method for making the app open in the center of screen
    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())


    # method for closing the program and managing the center and verifier processes
    def closeEvent(self, event):
        if self.centersList:
            self.CloseCentersSockets()
        if self.verifier:
            self.CloseVerifier()
        event.accept() #accept the close event


    # method for closing sockets of voting centers 
    def CloseCentersSockets(self):
        if self.centersList:
            # send message to centers that they should exit
            for centerSocket, centerSharedKey, centerSharedIv in self.centersList:
                closeMessage = (False, 'Exit') #message to tell center to finish
                centerSocket.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(closeMessage), centerSharedKey, centerSharedIv)) #send encrypted exit message

            #closing the centers sockets before closing app
            for center in self.centersList:
                center[0].close()
        print('Centers exited successfully')
    

    # method for closing verifier server
    def CloseVerifier(self):
        if self.verifier:
            # send message to verifier that he should exit
            verifierSocket, verifierSharedKey, verifierSharedIv = self.verifier #get verifier socket, shared key and iv
            closeMessage = (False, 'Exit') #message to tell verifier to finish
            verifierSocket.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(closeMessage), verifierSharedKey, verifierSharedIv)) #send encrypted exit message
            verifierSocket.close() #closing verifier socket before closing app
        print('Verifier exited successfully')


    # method for initializing database connection
    def initDBConnection(self):
        self.dbConn = SQLHelper.GetDBConnection()
        if not self.dbConn:
            self.UpdateInfoLabel('Couldn\'t connect to database, try again later.')
            return False
           
        # update voter counter and vote results in gui
        if not self.UpdateVoterCounter() or not self.UpdateResults():
            self.UpdateInfoLabel('Couldn\'t featch voters information from database.')
            return False

        return True

    
    # method for setting input validators on line edits in gui
    def initValidators(self):
        # regex expressions for validation
        idRegex = QRegExp(r'^\d{9}$') #id must be 9 digits
        passRegex = QRegExp(r'^.{6,16}$') #password at least 6 characters
        infoRegex = QRegExp(r'^[A-Za-z\s]{2,20}$') #info at least 2 characters
        addressRegex = QRegExp(r'^[A-Za-z0-9\s,.-]{2,20}$') # address also includes special chars

        # set validaotrs for id and password in main screen
        self.idLineEdit.setValidator(QRegExpValidator(idRegex))
        self.passLineEdit.setValidator(QRegExpValidator(passRegex))
        # set validators for form in voter submit
        self.FirstNameLineEdit.setValidator(QRegExpValidator(infoRegex))
        self.LastNameLineEdit.setValidator(QRegExpValidator(infoRegex))
        self.AddressLineEdit.setValidator(QRegExpValidator(addressRegex))
        self.CityLineEdit.setValidator(QRegExpValidator(infoRegex))
        self.StateLineEdit.setValidator(QRegExpValidator(infoRegex))
        self.IdLineEdit.setValidator(QRegExpValidator(idRegex))
        self.PassLineEdit.setValidator(QRegExpValidator(passRegex))


    # method to update voter counter in gui using database info
    def UpdateVoterCounter(self):
        # set the vote counter in gui using database info
        notVoted = SQLHelper.CheckAllVotersStatus(self.dbConn)
        if notVoted != -1:
            self.UpdateCounterLabel(str(notVoted))
            return True
        else:
            return False
        
    
    # method to update results from database
    def UpdateResults(self):
        results = SQLHelper.GetTotalResults(self.dbConn)
        if not results:
            print('Couldn\'t feach results from database.')
            return False
        
        # calculate total votes
        demVotes, repVotes = results[0], results[1]
        totalVotes = demVotes + repVotes
        
        # check if there are no votes we return 0 for each
        if totalVotes == 0:
            self.demVote.setText('0' + '%')
            self.repVote.setText('0' + '%')
            print('No votes have been cast.')
            return True
        
        # calculate percentages for each party
        demPercentage = int((demVotes / totalVotes) * 100)
        repPercentage = int((repVotes / totalVotes) * 100)
        self.demVote.setText(str(demPercentage) + '%')
        self.repVote.setText(str(repPercentage) + '%')
        print(f'Democratic Votes: {demPercentage}%')
        print(f'Republican Votes: {repPercentage}%\n')
        return True
            

    # method for toggle voter UI
    def ToggleVerificationUI(self, enable=True):
        if enable:
            self.idLineEdit.setEnabled(True)
            self.passLineEdit.setEnabled(True)
            self.verifyButton.setEnabled(True)
            self.addVoterButton.setEnabled(True)
        else: 
            self.idLineEdit.setEnabled(False)
            self.passLineEdit.setEnabled(False)
            self.verifyButton.setEnabled(False)
            self.addVoterButton.setEnabled(False)


    # method for toggle voter UI 
    def ToggleVoterUI(self, show=True):
        if show:
            self.chooseLabel.show()
            self.demButton.show()
            self.repButton.show()
        else: 
            self.chooseLabel.hide()
            self.demButton.hide()
            self.repButton.hide()


    # method for updating counter label in gui
    def UpdateCounterLabel(self, num):
        self.voteCounter.setText(num)


    # method for updating info label in gui
    def UpdateInfoLabel(self, text):
        self.infoLabel.setText(text)
    

    #method for updating submit info label in gui
    def UpdateSubmitInfoLabel(self, text):
        self.SubmitInfoLabel.setText(text)


    # method for updating id and password
    def UpdateIdPass(self, id, password):
        self.idLineEdit.setText(id)
        self.passLineEdit.setText(password)


    # method for updating voter info labels in gui
    def UpdateVoterInfo(self, name, address, city, state):
        self.name.setText(name)
        self.address.setText(address)
        self.city.setText(city)
        self.state.setText(state)
    

    # method for setting submit info values
    def UpdateSubmitInfo(self, firstName, lastName, address, city, state, id, password):
        self.FirstNameLineEdit.setText(firstName)
        self.LastNameLineEdit.setText(lastName)
        self.AddressLineEdit.setText(address)
        self.CityLineEdit.setText(city)
        self.StateLineEdit.setText(state)
        self.IdLineEdit.setText(id)
        self.PassLineEdit.setText(password)
    

    # method to get submit info from gui
    def GetSubmitInfo(self):
        submitInfo = {
            'firstName': self.FirstNameLineEdit.text(),
            'lastName': self.LastNameLineEdit.text(),
            'address': self.AddressLineEdit.text(),
            'city': self.CityLineEdit.text(),
            'state': self.StateLineEdit.text(),
            'id': self.IdLineEdit.text(),
            'password': self.PassLineEdit.text()
        }
        return submitInfo


    # method for showing voter submission page
    def ShowVoterSubmit(self):
        self.UpdateVoterInfo('', '', '', '')
        self.UpdateIdPass('', '')
        self.UpdateInfoLabel('')
        self.ToggleVoterUI(False)
        self.stackedWidget.setCurrentIndex(1)


    # method for showing main window of app
    def ShowMainWindow(self):
        self.UpdateSubmitInfo('', '', '', '', '', '', '')
        self.UpdateSubmitInfoLabel('')
        self.stackedWidget.setCurrentIndex(0)


    # method for checking if ip and password are valid
    def CheckIdPassword(self, id, password):
        # regex for validating ID and password
        idRegex = QRegExp(r'^\d{9}$') #matches exactly 9 digits
        passRegex = QRegExp(r'^.{6,16}$') #matches 6 or more characters
        
        # check that both fields are filled
        if not id or not password:
            self.UpdateInfoLabel('Please fill all required fields.')
            return False

        # check if both ID and password do not matche the regex
        if not idRegex.exactMatch(id) and not passRegex.exactMatch(password):
            self.UpdateInfoLabel('ID must be 9 digits and password at least 6 characters.')
            return False

        # check if id does'nt matche the regex
        elif not idRegex.exactMatch(id):
            self.UpdateInfoLabel('ID must be exactly 9 digits.')
            return False
        
        # check if the password does'nt matche the regex
        elif not passRegex.exactMatch(password):
            self.UpdateInfoLabel('Password must be at least 6 characters long.')
            return False

        return True

    
    # method for checking if voter submit info is valid
    def CheckSubmitInfo(self, submitInfo):
        # regex expressions for validation
        idRegex = QRegExp(r'^\d{9}$') #id must be 9 digits
        passRegex = QRegExp(r'^.{6,16}$') #password at least 6 characters
        errorMessage = '' #represents error message to show voter
        
        # check that all fields are filled
        if any(not submitInfo[field] for field in ['firstName', 'lastName', 'address', 'city', 'state', 'id', 'password']):
            self.UpdateSubmitInfoLabel('Please fill all required fields.')
            return False

        # check if any field is at least 2 characters long
        if  any(len(submitInfo[field].strip().replace(' ', '')) < 2 for field in ['firstName', 'lastName', 'address', 'city', 'state']):
            errorMessage += 'Information fields must be at least 2 characters long.\n'

        # check if both ID and password do not matche the regex
        if not idRegex.exactMatch(submitInfo['id']) and not passRegex.exactMatch(submitInfo['password']):
            errorMessage += 'ID must be 9 digits and password at least 6 characters.'

        # check if id does'nt matche the regex
        elif not idRegex.exactMatch(submitInfo['id']):
            errorMessage += 'ID must be exactly 9 digits.'
        
        # check if the password does'nt matche the regex
        elif not passRegex.exactMatch(submitInfo['password']):
            errorMessage += 'Password must be at least 6 characters long.'
        
        if errorMessage:
            self.UpdateSubmitInfoLabel(errorMessage)
            return False

        return True


    # method for adding a voter to application
    def AddVoterToApp(self):
        voterInfo = self.GetSubmitInfo()

        #check if user submmited valid input
        if not self.CheckSubmitInfo(voterInfo):
            return False
        
        #process the voter information and add him to our database with sha256 for id and pass
        result = SQLHelper.AddVoter(
            self.dbConn, DH_RSA.ToSHA256(voterInfo['id'], toHex=True), DH_RSA.ToSHA256(voterInfo['password'], toHex=True), 
            voterInfo['firstName'], voterInfo['lastName'],
            voterInfo['address'], voterInfo['city'], voterInfo['state']
        )

        #check result and inform user if an error occured
        if result == -1:
            self.UpdateSubmitInfoLabel('Failed adding voter to database, try again later.')
            return False
        elif result == 0:
            self.UpdateSubmitInfoLabel('Voter ID already exists in system, try another one.')
            return False
        else:
            self.UpdateInfoLabel('Added new registered voter to system.')
            self.UpdateVoterCounter()
            self.ShowMainWindow()
            return True


    # method for verifing voter using ZKP graph isomorphism
    def VerifyVoter(self):
        # clear user info and hide voting ui
        self.UpdateVoterInfo('', '', '', '')
        self.ToggleVoterUI(False)

        # first check that user filled correct info with regex
        if self.CheckIdPassword(self.idLineEdit.text(), self.passLineEdit.text()):
            # initial verification message for user
            self.UpdateInfoLabel('Verifing voter credentials, please wait.')
            self.ToggleVerificationUI(False)

            # initialize ZKP graph isomorphism test to authenticate the voter
            verifierSocket, verifierSharedKey, verifierSharedIv = self.verifier #get verifier socket, shared key and iv
            verifyMessage = (True, 'Verify') #represents message that tells verify that we want to start verification
            verifierSocket.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(verifyMessage), verifierSharedKey, verifierSharedIv)) #encrypt the verify message
            result = ZKP_Graph.StartVerification(verifierSocket, verifierSharedKey, verifierSharedIv, port=9000) #start ZKP verification with verifier

            #check if verification faild
            if not result:
                self.UpdateInfoLabel('Failed authenticating voter, please try again later.')
                self.ToggleVerificationUI(True)
                return False
            
            # verification was succcesssful, we now check if voter id is valid
            self.voterId = DH_RSA.ToSHA256(self.idLineEdit.text(), toHex=True) #get given voter id
            voterPass = DH_RSA.ToSHA256(self.passLineEdit.text(), toHex=True) #get given voter pass

            # check if voter exists in db, if so mark it as voted and process his vote
            if self.voterId and voterPass:
                isVoted = SQLHelper.CheckVoterStatus(self.dbConn, self.voterId)
                isAuth = SQLHelper.AuthVoter(self.dbConn, self.voterId, voterPass)

                # check if either voter doesn't exists or password is invalid
                if isVoted == -1 or not isAuth:
                    self.UpdateInfoLabel('Couldn\'t find voter in voting system, check back later...')
                    self.ToggleVerificationUI(True)
                    return False
                # if voter is authenticated and password correct
                elif isAuth:
                    # initialzie voter info in gui from database
                    voterInfo = SQLHelper.GetVoterInfo(self.dbConn, self.voterId)
                    if voterInfo:
                        name = voterInfo['firstName'] + ' ' + voterInfo['lastName']
                        address = voterInfo['address']
                        city, state = voterInfo['city'], voterInfo['state']
                        self.UpdateVoterInfo(name, address, city, state)
                        #if voter already voted we notify him in gui
                        if isVoted == 1:
                            self.UpdateInfoLabel('Voter is already registered as voted, cannot proceed.')
                            self.ToggleVerificationUI(True)
                            return False
                        # else voter is valid for voting
                        elif isVoted == 0:
                            self.UpdateInfoLabel('Voter authenticated successfully, you can start voting.')
                            self.ToggleVerificationUI(True)
                            self.ToggleVoterUI(True) #show voting ui
                            return True
                    else:
                        self.UpdateInfoLabel('Couldn\'t fetch voter info from database, check back later...')
                        self.ToggleVerificationUI(True)
                        return False
            else:
                self.UpdateInfoLabel('Couldn\'t fetch voter info from database, check back later...')
                self.ToggleVerificationUI(True)
                return False

            
    # method for processing voter's vote to centers using secure connections
    def ProcessVote(self, choice):
        failedCenters = 0 #represents number of failed centers
        try:
            # we first send vote to centers for them to update their tally
            for centerSocket, centerSharedKey, centerSharedIv in self.centersList:

                # send encrypted choice to center for tally
                voterChoice = (True, choice) #represents the choice of voter, true indicates vote for tallying
                centerSocket.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(voterChoice), centerSharedKey, centerSharedIv)) #encrypt the vote and send it to center

                # receive the result if center succeed in updating their tally
                resultData = centerSocket.recv(4096) 
                result = pickle.loads(DH_RSA.AES_Decrypt_CBC(resultData, centerSharedKey, centerSharedIv)) #decrypt the result from center

                #if center failed to update its tally we increment failed counter
                if not result:
                    failedCenters += 1

            # check if voting centers processes the tallying
            if failedCenters <= 1:
                if self.dbConn and self.voterId:
                    if SQLHelper.SetVoterStatus(self.dbConn, self.voterId, status=1):
                        # set the vote counter after vote is registered
                        if not self.UpdateVoterCounter() or not self.UpdateResults():
                            self.UpdateInfoLabel('Couldn\'t featch voters information from database.')
                            return False
                        # inform user for registered vote
                        self.UpdateInfoLabel('Vote registered successfully, thank you for your time.')
                        self.ToggleVoterUI(False)
                        return True
                    else:
                        self.UpdateInfoLabel('Could\'nt process vote, try again later.')
                        self.ToggleVoterUI(False)
                        return False
            else:
                self.UpdateInfoLabel('Could\'nt process vote, try again later.')
                self.ToggleVoterUI(False)
                return False

        except Exception as e:
            print(f'Main app: Error occurred: {e}')
            self.UpdateInfoLabel('Could\'nt process vote, try again later.')
            self.ToggleVoterUI(False)

#--------------------------------------------------------SECURE-VOTE-END--------------------------------------------------------#

#-----------------------------------------------------INIT-PROCESSES-THREAD-----------------------------------------------------#
# thread for initializing centers and ZKP verifier server
class Init_Processes_Thread(QThread):
    # define signals for updating info label and verification UI in gui
    updateInfoLabelSignal = pyqtSignal(str)
    updateVerificationUISignal = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent

    def run(self):
        try:
            self.updateInfoLabelSignal.emit('Connecting to verifier and voting centers, please wait...')
            verifier = None
            centersList = []
            verifierPort = 9000 #we set verifier on port 4050
            centerport = 4050 #we set centers on ports 4050-4052

            # initialize verifier server for ZKP graph isomorphism authentication using Diffie-Hellman and RSA
            verifier = Verifier.InitVerifier(port=verifierPort)

            # initialize 3 centers for processing votes using Diffie-Hellman and RSA
            for centerId in range(1, 4):
                center = Center.InitCenter(centerId, port=centerport) #represented as tuple (centerSocket, centerSharedKey, centerSharedIv)
                centersList.append(center) #append center tuple to list
                centerport += 1 #process next center on the next port

            # update the verifier and centersList attributes in the main thread
            if self.parent:
                self.parent.verifier = verifier
                self.parent.centersList = centersList

            # after finishing, emit the signal to update the GUI
            self.updateInfoLabelSignal.emit('Connected successfully, you can now start voting.')
            self.updateVerificationUISignal.emit(True)
            print(f'Init_Processes_Thread: Finished connecting to ZKP verifier and voting centers.\n')
        except Exception as e:
            self.updateInfoLabelSignal.emit('Failed connecting to verifier and voting centers, try again later.')
            print(f'Init_Processes_Thread: Error occurred: {e}')

#------------------------------------------------------------MAIN---------------------------------------------------------------#

if __name__ == '__main__':
    #start SecureVote application
    app = QApplication(sys.argv)
    secureVote = SecureVote()
    try:
        sys.exit(app.exec_())
    except:
        print('Exiting')