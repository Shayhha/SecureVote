import sys, os, socket, pickle, math, random, time, string, multiprocessing, psycopg
from abc import ABC
from dotenv import load_dotenv
from Crypto.Util.number import getPrime
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from interface.ui_SecureVote import Ui_SecureVote
from PySide6.QtCore import Signal, Slot, QObject, QThread, QRegularExpression
from PySide6.QtGui import QGuiApplication, QIcon, QValidator, QRegularExpressionValidator
from PySide6.QtWidgets import QApplication, QMainWindow
from PySide6.QtNetwork import QLocalServer, QLocalSocket

currentDir = os.path.dirname(os.path.abspath(__file__)) #represents current directory

#-----------------------------------------------------------ZKP-GRAPH-----------------------------------------------------------#
#class that represents ZKP graph isomorphism problem
class ZKP_Graph(ABC):

    # function that creates directed/undirected graph with n vertices and m edges
    @staticmethod
    def CreateGraph(n: int, m: int, isDirected: bool=False) -> dict:
        # check if m is greater than the maximum possible edges
        maxEdges = (n * (n - 1)) // 2 if not isDirected else n * (n - 1) #max number of edges in a simple graph
        if m > maxEdges:
            raise ValueError(f'Error, invalid number of edges. A graph with {n} vertices can have at most {maxEdges} edges.')

        graph = {i: [] for i in range(1, n + 1)} #create a dict represented as vertexes as keys (numerical)
        edges = set() #create a set of edges 
        
        # iterate over in loop and add m edges to our graph
        while len(edges) < m:
            u = random.randint(1, n) #create random u vertex
            v = random.randint(1, n) #create random v vertex
            
            # check that u != v becasue we dont want loops in graph
            if u != v:
                if isDirected: #if true we add the edge as a directed edge
                    if (u, v) not in edges: #check that edge doesnt exists already
                        edges.add((u, v)) #add edge to edges set
                        graph[u].append(v) #add v to adjacency list of u
                else: #else we add edge as undirected edge
                    if (u, v) not in edges and (v, u) not in edges: #check that edge doesnt exists already
                        edges.add((u, v)) #add edge to edges set
                        graph[u].append(v) #add v to adjacency list of u
                        graph[v].append(u) #add u to adjacency list of v

        return graph


    # function that creates isomorphic graph by permuting the vertices and mapping them to letters, returns premuted graph and permutation
    @staticmethod
    def CreatePermutedGraph(graph: dict) -> tuple:
        vertices = list(graph.keys()) #create list of all vertices from graph
        random.shuffle(vertices) #shuffle vertices for random permutation

        # map each vertex to a unique character starting from letter "a"
        letters = list(string.ascii_lowercase[:len(vertices)]) #create list of characters 
        permutation = {vertices[i]: letters[i] for i in range(len(vertices))} #map each numerical vertex in graph to its unique letter
        
        # apply the mapping to create the permuted graph with letter labeled vertices
        permutedGraph = {permutation[vertex]: [] for vertex in vertices} #create new graph that holds our new mapped vertices
        for vertex in vertices: #iterate over graph dict and add its corresponding neighbors 
            permutedGraph[permutation[vertex]] = [permutation[neighbor] for neighbor in graph[vertex]] #add corresponding neighbors based on mapping
        
        return permutedGraph, permutation
    

    # method for initiating a connection with verifier (server) and starting verification, prover side (client)
    @staticmethod
    def StartVerification(clientSocket: socket.socket, secretKey: bytes, iv: bytes, port: int=4050, isAnswer: bool=True) -> bool:
        rounds = 10 #represnets number of rounds for verification
        decision = None #represents the decision of verifier for zkp test

        try:
            print(f'ZKP_Client: Starting ZKP Graph verification with verifier on port {port}.')

            # create our graph and permutation and send verifier its graph for verification
            graphProver = ZKP_Graph.CreateGraph(12,16) #create prover's graph (G)
            graphVerifier, permutation = ZKP_Graph.CreatePermutedGraph(graphProver) #create premuted graph (H) for verifier
            clientSocket.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(graphVerifier), secretKey, iv)) #send encrypted initial response with verifier's premuted graph (H)

            # iterate through 10 rounds with the verifier to prove that we know the secret permutation
            for _ in range(rounds):

                # get verifier's data and save the question with loads
                verifierData = clientSocket.recv(4096) #get initial binary data from verifier
                verifierQuestion = pickle.loads(DH_RSA.AES_Decrypt_CBC(verifierData, secretKey, iv)) #decrypt and save verifier's question
                verifierVertex = verifierQuestion[1] #save verifier's given vertex
                
                # verifiers question is tuple ([1,0], permutedVertex) and 1 means we answers correctly to previous answer, 0 if not
                if isAnswer: #if true we answer correctly with permutation dict
                    originalVertex = None #represnets original vertex coresponing with verifier's vertex

                    # iterate over permutation dict and find matching vertex
                    for vertex, permutedVertex in permutation.items():
                        if permutedVertex == verifierVertex: #if true we found the matching vertex to verifier's permuted vertex
                            originalVertex = vertex #save vertex for later use
                            break

                    # if we found the correct vertex we send it to verifier
                    if originalVertex is not None:
                        permutedNeighbors = [permutation[neighbor] for neighbor in graphProver[originalVertex]] #create matching permuted neighbor list
                        clientSocket.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(permutedNeighbors), secretKey, iv)) #send encrypted result to verifier server
                        print('ZKP_Client: Answer sent to verifier!')

                else: #else we guess the adjacency list
                    numOfNeigbors = random.randint(0, len(graphProver)) #guess number from 0 to number of vertices in graph
                    guessedNeighbors = list(string.ascii_lowercase[:numOfNeigbors]) #create list of neighbors represented as letters
                    clientSocket.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(guessedNeighbors), secretKey, iv)) #send encryptd guess to verifier server 
                    print('ZKP_Client: Guess sent to verifier!')
            
            # get verifer's result at the end ([1,0] - last round result, resultPersentage)
            verifierResultData = clientSocket.recv(4096) #get final result from verifier
            verifierResult = pickle.loads(DH_RSA.AES_Decrypt_CBC(verifierResultData, secretKey, iv)) #decrypt and save the result

            # print result whether verifier is convinced that prover knowns the permutation
            if verifierResult[1] >= 0.9: #if he is convinced
                print(f'ZKP_Client: Verifer is convinced that prover knowns the permutation, prover answered {verifierResult[1] * 100}% correct.')
                decision = True
            else: #else prover failed to convince the verifier 
                print(f'ZKP_Client: Verifer is not convinced that prover knowns the permutation, prover answered {verifierResult[1] * 100}% correct.')
                decision = False
        except Exception as e:
            print(f'ZKP_Client: Error occurred: {e}.') #print exception if occurred
        finally:
            return decision


    # method for initiating a connection with client (prover) and starting the test, verifier side (server)
    @staticmethod
    def StartVerifier(serverSocket: socket.socket, secretKey: bytes, iv: bytes, port: int=4050) -> None:
        graphVerifier = None
        rounds = 10 #represnets number of rounds for verification
        answeredCorrectly = 0 #represents the number of correct answers from prover
        previousResult = 0 #represents previous result, 1 - prover was correct, 0 - prover was incorrect
        usedVertices = set() #represnets previously chosen vertices

        try:
            print(f'ZKP_Verifier: Starting ZKP Graph verification with client on port {port}.')

            # recive the verifier graph and save it for later use
            graphVerifierData = serverSocket.recv(4096) #get initial binary data from client
            graphVerifier = pickle.loads(DH_RSA.AES_Decrypt_CBC(graphVerifierData, secretKey, iv)) #decrypt and save verifier's graph (H) given from prover
            if graphVerifier != None:
                print(graphVerifier)

            # iterate through 10 rounds with the client (prover) to check that he knows the secret permutation
            for _ in range(rounds):
                # select a random vertex that has not been chosen before
                vertices = list(graphVerifier.keys() - usedVertices) #exclude previously chosen vertices
                if not vertices: #if no remaining vertices, reset the usedVertices set
                    usedVertices.clear()
                    vertices = list(graphVerifier.keys())
                chosenVertex = random.choice(vertices) # choose a random vertex from vertices list
                usedVertices.add(chosenVertex) #mark the chosen vertex as used

                serverSocket.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps((previousResult, chosenVertex)), secretKey, iv)) #send encrypted question to prover client

                proverAnswerData = serverSocket.recv(4096) #get prover answer data from client
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

            # encrypt and send last response to prover with its last result and total result in test
            serverSocket.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps((previousResult, answeredCorrectly / rounds)), secretKey, iv))
            print(f'ZKP_Verifier: Sent result of verification to client.')
        except Exception as e:
            print(f'ZKP_Verifier: Error occurred: {e}.') #print exception if occurred


    # method that returns permutation of graph
    def GetPermutation(permutation: dict) -> str:
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
    def ToNumber(message: str | bytes) -> int:
        # if message is string we encode it
        if isinstance(message, str):
            message = message.encode()
        return int.from_bytes(message, byteorder='big')


    # method to convert to bytes
    @staticmethod
    def ToByte(message: int | str) -> bytes:
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
    def ToString(message: int | bytes) -> str:
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
    def GetRSAKeys(rsaKeyLength: int=2048, e: int=65537) -> tuple:
        # represents our parameters for RSA algorithm
        publicKey, privateKey = None, None #represents our public and private keys 
        p, q, n, phi, e = None, None, None, None, None #represents parameters to calculate the keys

        # iterate in loop and try to generate two large distinct prime numbers
        while True:
            p, q = getPrime(rsaKeyLength), getPrime(rsaKeyLength) #generate the prime numbers with desired length
            if p != None and q != None and p != q: #means we generated different prime numbers, we break
                break

        # compute n and phi
        n = p * q #apply the formula for n
        phi = (p - 1) * (q - 1) #apply the formula for phi

        if e == None: #if true then we calcuate e for generating d
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
    def RSA_Encrypt(plaintext: int | str | bytes, publicKey: int) -> int:
        n, e = publicKey #represents public key (n, e)
        
        # if true we received plaintext as string or bytes so we convert to number
        if isinstance(plaintext, str) or isinstance(plaintext, bytes):
            plaintext = DH_RSA.ToNumber(plaintext) #convert the plaintext to a number
        
        # encrypt the plaintext number using RSA formula: ciphertext = plaintext^e % n
        ciphertext = pow(plaintext, e, n)
        
        return ciphertext


    # method to decrypt plaintext using RSA decryption 
    @staticmethod
    def RSA_Decrypt(ciphertext: int | str | bytes, privateKey: int, toStr: bool=False, toByte: bool=False) -> int | str | bytes:
        n, d = privateKey #represents private key (n, d)

        # if true we received ciphertext as string or bytes so we convert to number
        if isinstance(ciphertext, str) or isinstance(ciphertext, bytes):
            ciphertext = DH_RSA.ToNumber(ciphertext) #convert the ciphertext to a number
        
        # decrypt the ciphertext using RSA formula: plaintext = ciphertext^d % n
        decipheredText = pow(ciphertext, d, n)
        
        # we check if we need to convert the decipheredText to string or bytes
        if toStr:
            decipheredText = DH_RSA.ToString(decipheredText) #convert the number back to string
        elif toByte:
            decipheredText = DH_RSA.ToByte(decipheredText) #convert the number back to bytes
        
        return decipheredText


    # method to encrypt plaintext using AES encryption in CBC mode
    @staticmethod
    def AES_Encrypt_CBC(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
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
    def AES_Decrypt_CBC(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
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
    def GetRandomBytes(length: int=16) -> bytes:
        return bytes(random.getrandbits(8) for _ in range(length))


    # method that returns sha-256 hash of given message
    @staticmethod
    def ToSHA256(message: int | str | bytes, toHex: bool=False) -> str:
        if not isinstance(message, bytes): #ensure the message is byte array
            message = DH_RSA.ToByte(message) #convert to string and then to bytes to ensure its bytes
        digest = Hash(SHA256()) #create a SHA256 hash object
        digest.update(message) #update the hash object with the message bytes
        return digest.finalize() if not toHex else digest.finalize().hex() #return sha-256 hash of message


    # method that creates digital signature from given message and rsa private key
    @staticmethod
    def CreateSignature(message: int | str | bytes, privateKey: int) -> int:
        messageHash = DH_RSA.ToSHA256(message) #create sha-256 hash of our message
        signature = DH_RSA.RSA_Encrypt(messageHash, privateKey) #enrypt message hash with private key and create signature
        # print(message.hex())
        # print(messageHash.hex())
        return signature #return signature


    # method that verifies given signature using rsa public key
    @staticmethod
    def VerifySignature(message: int | str | bytes, signature: int, publicKey: int) -> bool:
        messageHash = DH_RSA.RSA_Decrypt(signature, publicKey) #decrypt signature and retrive message hash using public key
        if not isinstance(messageHash, bytes): #ensure that message hash is bytes
            messageHash = DH_RSA.ToByte(messageHash) #convert message hash to bytes with our method
        # print(message.hex())
        # print(messageHash.hex())
        return DH_RSA.ToSHA256(message) == messageHash #return if signature hash matches our message hash


    # method that creates AES key used KDF with diffie hellman shared secret
    @staticmethod
    def GetAESKey(value: int | bytes, salt: int | bytes, keyLength: int=128) -> bytes:
        # convert the shared secret to bytes
        if isinstance(value, int):
            value = DH_RSA.ToByte(value)

        # convert the salt to bytes
        if isinstance(salt, int):
            salt = DH_RSA.ToByte(salt)

        # check if key length is valid, if not throw exception
        if keyLength != 128 and keyLength != 192 and keyLength != 256:
            raise ValueError('Error, AES key length is invalid.')

        # derive the AES key using HKDF using shared secret
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
    def DH_Client(clientSocket: socket.socket, primeLength: int=2048, port: int=4050) -> tuple:
        try:
            print(f'DH_Client: Starting secure connection with DH_Server on port {port}.')

            # initial parameters both parties will use for DH key exchange
            p = getPrime(primeLength) #represents the prime number both parties will use
            alpha = random.randint(2, p - 2) #represents the chosen alpha parameter for key exchange

            # create client public and private keys for RSA
            clientPublicKey, clientPrivateKey = DH_RSA.GetRSAKeys()

            # receive the server's rsa public key and initate secure diffie hellman key exchange
            serverPublicKeyData = clientSocket.recv(4096) #get initial binary data from server with our rsa public key
            serverPublicKey = pickle.loads(serverPublicKeyData) #save our server public key we received for later use

            # send client public key to server for secure diffie hellman key exchange
            clientSocket.sendall(pickle.dumps(clientPublicKey)) 

            # send client digital signature to server for mutual authentication
            clientMessage = DH_RSA.GetRandomBytes() #create message for client signature
            clientSignature = DH_RSA.CreateSignature(clientMessage, clientPrivateKey) #create signature using client private key
            clientSocket.sendall(pickle.dumps((clientMessage, clientSignature))) #send client message and signature to server

            # receive server's signature and verify its authenticity
            serverSignatureData = clientSocket.recv(4096) #get server signature data
            serverMessage, serverSignature = pickle.loads(serverSignatureData) #get server message and signature
            if not DH_RSA.VerifySignature(serverMessage, serverSignature, serverPublicKey): #check if authentication failed
                raise RuntimeError('DH_Client: Digital signature verification failed with server!\n')
            else: #else we print successful authentication
                print('DH_Client: Digital signature verification successful with server!\n')

            # we choose our "a" secret parameter and calculate "A" public parameter for first party
            a = random.randint(1, p - 1) #represents the chosen "a" seccret parameter
            A = pow(alpha, a, p) #calculate public key to send to second party with formula: alpha^a % p

            # encrypt our dh parameters with server public key and send them to server
            encryptedParams = (DH_RSA.RSA_Encrypt(p, serverPublicKey), DH_RSA.RSA_Encrypt(alpha, serverPublicKey), DH_RSA.RSA_Encrypt(A, serverPublicKey))
            clientSocket.sendall(pickle.dumps(encryptedParams)) 

            # receive the server's B parameter, secret salt, iv and calcuate our shared secret
            dhParamData = clientSocket.recv(4096) #get binary data from server with his B parameter and secret salt
            B, secretSalt, iv = pickle.loads(dhParamData) #save B parameter for calculation of secret
            B, secretSalt, iv = DH_RSA.RSA_Decrypt(B, clientPrivateKey), DH_RSA.RSA_Decrypt(secretSalt, clientPrivateKey, toByte=True), DH_RSA.RSA_Decrypt(iv, clientPrivateKey, toByte=True) #decrypt the parameters using client public key

            # calculate the shared secret and generate aes key with salt
            S = pow(B, a, p) #calculate shared secret
            secretKey = DH_RSA.GetAESKey(S, secretSalt) #create aes key with kdf and secret salt
            print(f'DH_Client: AES key: {secretKey.hex()} IV: {iv.hex()}\n') #print aes key and iv of client

            # finally we return socket, aes key and iv for communicating with server
            return clientSocket, secretKey, iv

        except Exception as e:
            print(f'DH_Client: Error occurred: {e}.') #print exception if occurred


    # method that represents server side in secure diffe hellman key exchange and authenticating client with rsa
    @staticmethod
    def DH_Server(serverSocket: socket.socket, port: int=4050) -> tuple:
        try:
            print(f'DH_Server: Connection established with DH_Client on port {port}.\n')

            # create server public and private keys for RSA 
            serverPublicKey, serverPrivateKey = DH_RSA.GetRSAKeys()
            
            # send server public key to client for secure diffie hellman key exchange
            serverSocket.sendall(pickle.dumps(serverPublicKey)) 

            # receive the client's rsa public key and initate secure diffie hellman key exchange
            clientPublicKeyData = serverSocket.recv(4096) #get initial binary data from client with our rsa public key
            clientPublicKey = pickle.loads(clientPublicKeyData) #save our public key we received for later use

            # receive client's signature and verify its authenticity
            clientSignatureData = serverSocket.recv(4096) #get client signature data
            clientMessage, clientSignature = pickle.loads(clientSignatureData) #get client message and signature
            if not DH_RSA.VerifySignature(clientMessage, clientSignature, clientPublicKey): #check if authentication failed
                raise RuntimeError('DH_Server: Digital signature verification failed with client!\n')
            else: #else we print successful authentication
                print('DH_Server: Digital signature verification successful with client!\n')
            
            # send server digital signature to client for mutual authentication
            serverMessage = DH_RSA.GetRandomBytes() #create message for server signature
            serverSignature = DH_RSA.CreateSignature(serverMessage, serverPrivateKey) #create signature using server private key
            serverSocket.sendall(pickle.dumps((serverMessage, serverSignature))) #send message and signature to client
            
            # receive p, alpha and A parametrs from client to calculate our parameters
            dhParametersData = serverSocket.recv(4096) #get initial binary data from client of diffie hellman parameters p and alpha
            p, alpha, A = pickle.loads(dhParametersData) #save diffie hellman parameters we got from client

            # decrypt dh parameters we received from client using server private key
            p, alpha, A = DH_RSA.RSA_Decrypt(p, serverPrivateKey), DH_RSA.RSA_Decrypt(alpha, serverPrivateKey), DH_RSA.RSA_Decrypt(A, serverPrivateKey)

            # we choose our "b" secret parameter and calculate "B" public parameter for first party
            b = random.randint(1, p - 1) #represents the chosen "b" secret parameter 
            B = pow(alpha, b, p) #calculate public key to send to second party with formula: alpha^a % p

            # finally send B parameter with shared KDF salt and iv to client to establish shared secret
            secretSalt = DH_RSA.GetRandomBytes() #retrive a 16 byte salt for KDF function
            iv = DH_RSA.GetRandomBytes() #retrive a 16 byte initialization vector for AES CBC algorithm
            encryptedParam = (DH_RSA.RSA_Encrypt(B, clientPublicKey), DH_RSA.RSA_Encrypt(secretSalt, clientPublicKey), DH_RSA.RSA_Encrypt(iv, clientPublicKey)) #encrypt parameters 
            serverSocket.sendall(pickle.dumps(encryptedParam))

            # calculate the shared secret and generate aes key with salt 
            S = pow(A, b, p) #calculate shared secret
            secretKey = DH_RSA.GetAESKey(S, secretSalt) #create aes key with KDF and secret salt
            print(f'DH_Server: AES key: {secretKey.hex()} IV: {iv.hex()}\n') #print aes key and iv of server

            # finally we return socket, aes key and iv for communicating with client
            return serverSocket, secretKey, iv

        except Exception as e:
            print(f'DH_Server: Error occurred: {e}.') #print exception if occurred

#-----------------------------------------------------------DH-RSA-END----------------------------------------------------------#

#-----------------------------------------------------------SQL-HELPER----------------------------------------------------------#
# class for SQL queries to our SecureVote database
class SQLHelper(ABC):

    # method for getting database connection for SecureVote SQL database
    @staticmethod
    def GetDBConnection() -> psycopg.Connection | None:
        # load environment variables from env file
        load_dotenv(dotenv_path=os.path.join(currentDir, 'config', '.env'))

        # try to connect to database with database credentials from env file
        try:
            dbConnection = psycopg.connect(
                host=os.getenv('DB_HOST'),
                dbname=os.getenv('DB_DATABASE'),
                port=os.getenv('DB_PORT', '5432'),
                user=os.getenv('DB_USER'),
                password=os.getenv('DB_PASSWORD'),
                connect_timeout=5,
                row_factory=psycopg.rows.dict_row
            )

            # return database connection
            return dbConnection

        # if exception occurred we return none
        except Exception as e:
            print(f'Database connection failed: {e}.')
            return None


    # method for authenticating voter and getting voter information from database
    @staticmethod
    def AuthVoter(connection: psycopg.Connection, voterId: int, password: str) -> dict | None:
        try:
            with connection.cursor() as cursor:
                query = '''
                    SELECT firstname, lastname, address, city, state 
                    FROM voters 
                    WHERE voterid = %s AND password = %s
                    '''
                cursor.execute(query, (voterId, password))
                result = cursor.fetchone()

                # check if result is none, then print an error
                if not result:
                    print(f'No voter found with voterId {voterId}.')
                    return None

                # return voter information as a dictionary
                voterInfo = {
                    'firstname': result['firstname'],
                    'lastname': result['lastname'],
                    'address': result['address'],
                    'city': result['city'],
                    'state': result['state']
                }
                return voterInfo

        except Exception as e:
            print(f'Error fetching voter info: {e}.')
            return None


    # method for adding new voter to database
    @staticmethod
    def AddVoter(connection: psycopg.Connection, voterId: int, password: str, firstname: str, lastname: str, address: str, city: str, state: str) -> int:
        try:
            with connection.cursor() as cursor:
                # first we check if the voterId already exists in the database
                checkQuery = '''
                    SELECT COUNT(*) AS count 
                    FROM voters 
                    WHERE voterid = %s
                    '''
                cursor.execute(checkQuery, (voterId,))
                result = cursor.fetchone()

                # if we found a voter registered with that id it means the voterId already exists
                if result['count'] > 0:
                    print(f'Voter with voterId {voterId} already exists.')
                    return 0

                # secondly we insert the new voter into the voters table
                voterQuery = '''
                    INSERT INTO voters (voterid, password, firstname, lastname, address, city, state) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    '''
                cursor.execute(voterQuery, (voterId, password, firstname, lastname, address, city, state))

                # check if operation was successful
                if cursor.rowcount == 0:
                    print(f'Failed inserting voter with voterId {voterId}.')
                    connection.rollback()
                    return -1

                # thirdly we add the voter data to the votes table with a default value for 'isvoted' as 0
                voteQuery = '''
                    INSERT INTO votes (voterid, isvoted) 
                    VALUES (%s, 0)
                    '''
                cursor.execute(voteQuery, (voterId,))

                # check if operation was successful
                if cursor.rowcount == 0:
                    print(f'Failed inserting voter data with voterId {voterId}.')
                    connection.rollback()
                    return -1

                print(f'Voter {voterId} successfully added to voting system.')

            connection.commit()
            return 1

        except Exception as e:
            connection.rollback()
            print(f'Error adding voter: {e}.')
            return -1


    # method for checking voter status in database (1 for voted, else 0)
    @staticmethod
    def CheckVoterStatus(connection: psycopg.Connection, voterId: int) -> int:
        try:
            with connection.cursor() as cursor:
                query = '''
                    SELECT isvoted 
                    FROM votes 
                    WHERE voterid = %s
                    '''
                cursor.execute(query, (voterId,))
                result = cursor.fetchone()

                # if found no voter with matching voter id we return -1
                if not result:
                    print(f'No voter found with voterId {voterId}.')
                    return -1

                # return vote status for later processing
                return result['isvoted']

        except Exception as e:
            print(f'Error checking voting status: {e}.')
            return -1 #return -1 in case of an error


    # method for checking all voters status in database, to determine how many votes remain
    @staticmethod
    def CheckAllVotersStatus(connection: psycopg.Connection) -> int:
        try:
            with connection.cursor() as cursor:
                query = '''
                    SELECT COUNT(*) AS count 
                    FROM votes 
                    WHERE isvoted = 0
                    '''
                cursor.execute(query)
                result = cursor.fetchone()

                # if found no voters in voting system we return -1
                if not result:
                    print('No voters found in voting system.')
                    return -1

                # if we received 0 from count it means all voters voted
                if result['count'] == 0:
                    print('All voters have voted.')
                else:
                    print(f'{result['count']} voters have not voted.')

                return result['count'] #return number of not-voted

        except Exception as e:
            print(f'Error checking voters status: {e}.')
            return -1 #return -1 in case of an error


    # method for setting voter status in database (1 for voted, else 0)
    @staticmethod
    def SetVoterStatus(connection: psycopg.Connection, voterId: int=-1, status: int=1, reset: bool=False) -> bool:
        try:
            with connection.cursor() as cursor:
                # if true it means we reset all voters back to 0 (not voted)
                if reset and voterId == -1:
                    query = '''
                        UPDATE votes 
                        SET isvoted = 0
                        '''
                    cursor.execute(query)

                    # check if operation was successful
                    if cursor.rowcount == 0:
                        print('Failed updating all voters status.')
                        connection.rollback()
                        return False

                    print('All voters have been reset to not voted.')

                # else we update the status of a specific voter
                else:
                    query = '''
                        UPDATE votes 
                        SET isvoted = %s 
                        WHERE voterid = %s
                        '''
                    cursor.execute(query, (status, voterId))

                    # check if operation was successful
                    if cursor.rowcount == 0:
                        print(f'Failed updating vote status with voterId {voterId}.')
                        connection.rollback()
                        return False

                    print(f'Vote status for voterId {voterId} updated to {status}.')

            connection.commit()
            return True

        except Exception as e:
            connection.rollback()
            print(f'Error updating voter status: {e}.')
            return False


    # method for updating results of center in database and also for reset
    @staticmethod
    def UpdateResults(connection: psycopg.Connection, centerId: int=-1, demInc: int=0, repInc: int=0, reset: bool=False) -> bool:
        try:
            with connection.cursor() as cursor:
                # if true it means we want to reset all center results back to 0
                if reset and centerId == -1:
                    query = '''
                        UPDATE results 
                        SET democratvotes = 0, republicanvotes = 0
                        '''
                    cursor.execute(query)

                    # check if operation was successful
                    if cursor.rowcount == 0:
                        print('Failed updating all centers results.')
                        connection.rollback()
                        return False

                    print('All centers results have been reset to 0.')

                # else we need to increment the result of specific center
                else:
                    query = '''
                        UPDATE results 
                        SET democratvotes = democratvotes + %s, republicanvotes = republicanvotes + %s 
                        WHERE centerid = %s
                        '''
                    cursor.execute(query, (demInc, repInc, centerId))

                    # check if operation was successful
                    if cursor.rowcount == 0:
                        print(f'Failed updating center results with centerId {centerId}.')
                        connection.rollback()
                        return False

                    print(f'Results updated for centerId {centerId}.')

            connection.commit()
            return True

        except Exception as e:
            connection.rollback()
            print(f'Error updating center results: {e}.')
            return False


    # method for calculating results from all centers in database and return final result
    @staticmethod
    def GetTotalResults(connection: psycopg.Connection) -> tuple | None:
        try:
            with connection.cursor() as cursor:
                query = '''
                    SELECT SUM(democratvotes) AS totaldem, SUM(republicanvotes) AS totalrep 
                    FROM results
                    '''
                cursor.execute(query)
                result = cursor.fetchone()

                # check if result is none, then print an error
                if not result:
                    print('Failed calculating total results.')
                    return None

                print(f'Total DemResults: {result['totaldem']}, Total RepResults: {result['totalrep']}')
                return result['totaldem'], result['totalrep'] #return results as tuple

        except Exception as e:
            print(f'Error calculating total results: {e}.')
            return None

#---------------------------------------------------------SQL-HELPER-END--------------------------------------------------------#

#------------------------------------------------------------VERIFIER-----------------------------------------------------------#
# class that represents verifier server that authenticates users with zkp graph isomorphism
class Verifier(ABC):

    # method for initializing verifier server with secure connection using Diffie-Hellman and RSA
    @staticmethod
    def InitVerifier(port: int=9000) -> tuple:
        try:
            # create new process for verifier server to try and initiate connection for key exchange
            serverProcess = multiprocessing.Process(target=Verifier.ProcessVerifier, args=(port,))
            serverProcess.daemon = True #makes server exit when main process exits
            serverProcess.start() #start server process
            time.sleep(1)

            # create client socket and try to connect to server
            clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create cilent socket
            clientSocket.connect(('localhost', port)) #try to connect to server on desired port

            # call our secure Diffie-Hellman key exchange to create secure connection with server
            clientSocket, secretKey, iv = DH_RSA.DH_Client(clientSocket, port=port)

            # finally return socket, aes key and iv for communicating with verifier
            return clientSocket, secretKey, iv

        except Exception as e:
            clientSocket.close() #close connection if exeption occurred
            print(f'Init verifier: Error occurred: {e}.') #print exception if occurred


    # method that represents verifier server for processing ZKP graph isomorphism verifications
    @staticmethod
    def ProcessVerifier(port: int=9000) -> None:
        try:
            # create server socket
            serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create server socket
            serverSocket.bind(('localhost', port)) #bind socket to desired port
            serverSocket.listen(1) #listen for coming connection from client (prover)
            print(f'ZKP_Server: Verifier server listening on port {port}...')

            # wait for incoming connections
            serverConnection, serverAddress = serverSocket.accept() #accpet connection when received 
            print(f'ZKP_Server: Connection established with client at {serverAddress}.')

            # call our secure Diffie-Hellman key exchange to create secure connection with client
            serverConnection, secretKey, iv = DH_RSA.DH_Server(serverConnection, port=port)

            # loop to handle incoming messages from application
            while True:
                # receive inital bytes from connection
                data = serverConnection.recv(4096)

                # decrypt given message and process it later
                message = pickle.loads(DH_RSA.AES_Decrypt_CBC(data, secretKey, iv))

                # if true we received a valid message from application
                if isinstance(message, tuple) and len(message) == 2:
                    # if true we received message to start zkp verification
                    if message[0] == True and message[1] == 'Verify':
                        ZKP_Graph.StartVerifier(serverConnection, secretKey, iv, port) #call verifier to verifiy client
                    # else it means we recevied a request to finish verifier process
                    elif message[0] == False and message[1] == 'Exit':
                        print(f'ZKP_Server: Exit command received. Shutting down server...')
                        break

                # else we recevied unknown message, we notify about it
                else:
                    print(f'ZKP_Server: Unknown message received: {message}.')
                    
        except Exception as e:
            print(f'ZKP_Server: Error occurred: {e}.') #print exception if occurred
        finally:
            serverConnection.close() #close connection
            serverSocket.close() #close socket
            print(f'ZKP_Server: Verifier on port {port} Exited.')

#----------------------------------------------------------VERIFER-END----------------------------------------------------------#

#------------------------------------------------------------CENTER-------------------------------------------------------------#
# class that represents voting centers that perfrom the tallying
class Center(ABC):

    # method for initializing voting center with secure connection using Diffie-Hellman and RSA
    @staticmethod
    def InitCenter(centerId: int, port: int=4050) -> tuple:
        try:
            # create new process for ceenter server to try and initiate connection for key exchange
            serverProcess = multiprocessing.Process(target=Center.ProccessCenter, args=(centerId, port,))
            serverProcess.daemon = True #makes server exit when main process exits
            serverProcess.start() #start server process
            time.sleep(1)

            # create client socket and try to connect to server
            clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create cilent socket
            clientSocket.connect(('localhost', port)) #try to connect to server on desired port

            # call our secure Diffie-Hellman key exchange to create secure connection with server
            clientSocket, secretKey, iv = DH_RSA.DH_Client(clientSocket, port=port)

            # finally return socket, aes key and iv for communicating with center
            return clientSocket, secretKey, iv

        except Exception as e:
            clientSocket.close() #close connection if exeption occurred
            print(f'Init Center {centerId}: Error occurred: {e}.') #print exception if occurred


    # method that represents center server for processing votes securly
    @staticmethod
    def ProccessCenter(centerId: int, port: int=4050) -> None:
        try:
            # create server socket for center
            serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create server socket
            serverSocket.bind(('localhost', port)) #bind socket to desired port
            serverSocket.listen(1) #listen for coming connection from client
            print(f'Center {centerId}: Center listening on port {port}...')

            # wait for incoming connections
            serverConnection, serverAddress = serverSocket.accept() #accpet connection when received
            print(f'Center {centerId}: Connection established with client at {serverAddress}.')

            # call our secure Diffie-Hellman key exchange to create secure connection with client
            serverConnection, secretKey, iv = DH_RSA.DH_Server(serverConnection, port=port)

            # create database connection for center
            dbConnection = SQLHelper.GetDBConnection()

            # loop to handle incoming messages from application
            while True:
                # receive inital bytes from connection
                data = serverConnection.recv(4096)

                # decrypt given message and process it later
                message = pickle.loads(DH_RSA.AES_Decrypt_CBC(data, secretKey, iv))

                # if true we received a valid message from application
                if isinstance(message, tuple) and len(message) == 2:
                    # if true it means we recevied a vote to process
                    if message[0] == True:
                        # received democrat vote, we increment the democrat counter
                        if message[1] == 'Democrat':
                            if SQLHelper.UpdateResults(dbConnection, centerId, demInc=1):
                                serverConnection.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(True), secretKey, iv)) #we send true to confirm the tally
                            else:
                                serverConnection.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(False), secretKey, iv)) #else we send false to notify for failuire
                        # received republican vote, we increment the republican counter
                        elif message[1] == 'Republican':
                            if SQLHelper.UpdateResults(dbConnection, centerId, repInc=1):
                                serverConnection.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(True), secretKey, iv)) #we send true to confirm the tally
                            else:
                                serverConnection.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(False), secretKey, iv)) #else we send false to notify for failuire

                    # else it means we recevied a request to finish center process
                    elif message[0] == False and message[1] == 'Exit':
                        print(f'Center {centerId}: Exit command received. Shutting down server...')
                        break
                # else we recevied unknown message, we notify about it
                else:
                    print(f'Center {centerId}: Unknown message received: {message}.')

        except Exception as e:
            print(f'Center {centerId}: Error occurred: {e}.') #print exception if occurred
        finally:
            serverConnection.close() #close connection
            serverSocket.close() #close socket
            dbConnection.close() #close db connection
            print(f'Center {centerId}: Center on port {port} Exited.')

#----------------------------------------------------------CENTER-END-----------------------------------------------------------#

#----------------------------------------------------------SECURE-VOTE----------------------------------------------------------#
# class that represents main app of secure voting system
class SecureVote(QMainWindow):
    ui: Ui_SecureVote = None #represents main ui object of GUI with all our objects
    server: QLocalServer = None #represents listening server for our app to make sure one instance is showing
    serverName: str = 'SecureVote' #represents our listening server name
    verifier: tuple = None #represents verifier with (verifierSocket, verifierAesKey, verifierIv) tuple
    centersList: list = [] #represents centers list with (centerSocket, centerAesKey, centerIv) tuples
    dbConnection: psycopg.Connection = None #represents our database connection
    voterId: int = None #represents voter id
    idValidator, passValidator, infoValidator, addressValidator = None, None, None, None #represents line edit validators

    # constructor of main gui application
    def __init__(self) -> None:
        super(SecureVote, self).__init__()
        self.ui = Ui_SecureVote() #set mainwindow ui object
        self.ui.setupUi(self) #load the ui file of SecureVote
        self.initUI() #call init method


    # method to initialize GUI methods and events
    def initUI(self) -> None:
        self.setWindowTitle('SecureVote') #set title of window
        self.setWindowIcon(QIcon(os.path.join(currentDir, 'images', 'SecureVoteTransparent.png'))) #set icon of window
        self.ui.CancelButton.clicked.connect(self.ShowMainWindow)
        self.ui.SubmitButton.clicked.connect(self.AddVoterToApp)
        self.ui.addVoterButton.clicked.connect(self.ShowVoterSubmit)
        self.ui.verifyButton.clicked.connect(self.VerifyVoter)
        self.ui.demButton.clicked.connect(lambda: self.ProcessVote('Democrat'))
        self.ui.repButton.clicked.connect(lambda: self.ProcessVote('Republican'))
        self.InitValidators()
        self.UpdateCounterLabel('0')
        self.UpdateVotesCounterLabels('0', '0')
        self.UpdateIdPass('', '')
        self.UpdateInfoLabel('')
        self.UpdateVoterInfo('', '', '', '')
        self.UpdateSubmitInfo('', '', '', '', '', '', '')
        self.UpdateSubmitInfoLabel('')
        self.ToggleVerificationUI(False)
        self.ToggleVoterUI(False)
        self.center() #make the app open in center of screen

        # call init db method, if connected successfully initialize voting centers
        if self.InitDBConnection():
            # start the processes initialization in a thread
            self.initProcessesThread = Init_Processes_Thread(self)
            # connect relevant signals for thread
            self.initProcessesThread.updateInfoLabelSignal.connect(self.UpdateInfoLabel)
            self.initProcessesThread.updateVerificationUISignal.connect(self.ToggleVerificationUI)
            self.initProcessesThread.start() #start init processes thread


    # method for making the app open in the center of screen
    def center(self) -> None:
        qr = self.frameGeometry()
        cp = QGuiApplication.primaryScreen().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())


    # method for closing the program and managing the center and verifier processes
    def closeEvent(self, event) -> None:
        if self.centersList:
            self.CloseCentersSockets()
        if self.verifier:
            self.CloseVerifier()
        if self.dbConnection:
            self.dbConnection.close()
        SecureVote.CloseServer() #close listening server
        event.accept() #accept the close event


    # function for initializing listening server for managing one instance
    @staticmethod
    def InitServer() -> bool:
        # check if server is already initialized
        if SecureVote.server:
            return True; #return true if already initialized

        # create server to listen for new instances
        SecureVote.server = QLocalServer()

        # check if failed to listen on our server name, if so we remove old entries and try again
        if not SecureVote.server.listen(SecureVote.serverName):
            SecureVote.server.removeServer(SecureVote.serverName) #clear server name entries
            # try to listen again for our server name, if failed we return false
            if not SecureVote.server.listen(SecureVote.serverName):
                SecureVote.server = None #set server back to none
                return False #return false to indicate failure
        return True #return true if server listening successfully


    # function for checking if listening server is running
    @staticmethod
    def CheckServer() -> bool:
        socket = QLocalSocket() #create socket for checking is server running
        socket.connectToServer(SecureVote.serverName) # try to connect to server
        # wait for server to response to our request,if we receive response we return true
        if socket.waitForConnected(100):
            return True #return true to indicate that server is running
        return False #return false to indicate that server is down


    # function for closing listening server
    @staticmethod
    def CloseServer() -> None:
        # check if listening server is initialized
        if SecureVote.server:
            SecureVote.server.close() #close listening server
            QLocalServer.removeServer(SecureVote.serverName) #remove server entry
            SecureVote.server = None #set server back to none


    # method for closing sockets of voting centers 
    def CloseCentersSockets(self) -> None:
        if self.centersList:
            # send message to centers that they should exit
            for centerSocket, centerSharedKey, centerSharedIv in self.centersList:
                closeMessage = (False, 'Exit') #message to tell center to finish
                centerSocket.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(closeMessage), centerSharedKey, centerSharedIv)) #send encrypted exit message

            # closing the centers sockets before closing app
            for center in self.centersList:
                center[0].close()
        print('Centers exited successfully.')


    # method for closing verifier server
    def CloseVerifier(self) -> None:
        if self.verifier:
            # send message to verifier that he should exit
            verifierSocket, verifierSharedKey, verifierSharedIv = self.verifier #get verifier socket, shared key and iv
            closeMessage = (False, 'Exit') #message to tell verifier to finish
            verifierSocket.sendall(DH_RSA.AES_Encrypt_CBC(pickle.dumps(closeMessage), verifierSharedKey, verifierSharedIv)) #send encrypted exit message
            verifierSocket.close() #closing verifier socket before closing app
        print('Verifier exited successfully.')


    # method for initializing database connection
    def InitDBConnection(self) -> bool:
        self.dbConnection = SQLHelper.GetDBConnection()
        if not self.dbConnection:
            self.UpdateInfoLabel('Couldn\'t connect to database, try again later.')
            return False
           
        # update voter counter and vote results in gui
        if not self.UpdateVoterCounter() or not self.UpdateResults():
            self.UpdateInfoLabel('Couldn\'t featch voters information from database.')
            return False

        return True


    # method for initializing input validators for line edits in gui
    def InitValidators(self) -> None:
        # initialize validators for line edits with regular expressions
        self.idValidator = QRegularExpressionValidator(QRegularExpression('^[0-9]{9}$'), self) #id must be 9 digits
        self.passValidator = QRegularExpressionValidator(QRegularExpression('^.{6,16}$'), self) #password at least 6 characters
        self.infoValidator = QRegularExpressionValidator(QRegularExpression('^[A-Za-z ]{2,20}$'), self) #info at least 2 characters
        self.addressValidator = QRegularExpressionValidator(QRegularExpression('^[A-Za-z0-9 ,._-]{2,20}$'), self) #address also includes special characters

        # set validators for id and password line edits in main screen
        self.ui.idLineEdit.setValidator(self.idValidator)
        self.ui.passwordLineEdit.setValidator(self.passValidator)
        # set validators for form line edits in voter submit
        self.ui.FirstNameLineEdit.setValidator(self.infoValidator)
        self.ui.LastNameLineEdit.setValidator(self.infoValidator)
        self.ui.AddressLineEdit.setValidator(self.addressValidator)
        self.ui.CityLineEdit.setValidator(self.infoValidator)
        self.ui.StateLineEdit.setValidator(self.infoValidator)
        self.ui.IdLineEdit.setValidator(self.idValidator)
        self.ui.PasswordLineEdit.setValidator(self.passValidator)


    # method to update voter counter in gui using database info
    def UpdateVoterCounter(self) -> bool:
        # set the vote counter in gui using database info
        notVoted = SQLHelper.CheckAllVotersStatus(self.dbConnection)
        if notVoted != -1:
            self.UpdateCounterLabel(str(notVoted))
            return True
        else:
            return False


    # method to update results from database
    def UpdateResults(self) -> bool:
        results = SQLHelper.GetTotalResults(self.dbConnection)
        if not results:
            print('Couldn\'t feach results from database.')
            return False
        
        # calculate total votes
        demVotes, repVotes = results[0], results[1]
        totalVotes = demVotes + repVotes
        
        # check if there are no votes we return 0 for each
        if totalVotes == 0:
            self.UpdateVotesCounterLabels('0', '0')
            print('No votes have been cast.')
            return True
        
        # calculate percentages for each party
        demPercentage = int((demVotes / totalVotes) * 100)
        repPercentage = int((repVotes / totalVotes) * 100)
        self.UpdateVotesCounterLabels(str(demPercentage), str(repPercentage))
        print(f'Democratic Votes: {demPercentage}%')
        print(f'Republican Votes: {repPercentage}%\n')
        return True


    # method for toggle voter UI
    @Slot(bool)
    def ToggleVerificationUI(self, enable: bool=True) -> None:
        if enable:
            self.ui.idLineEdit.setEnabled(True)
            self.ui.passwordLineEdit.setEnabled(True)
            self.ui.verifyButton.setEnabled(True)
            self.ui.addVoterButton.setEnabled(True)
        else: 
            self.ui.idLineEdit.setEnabled(False)
            self.ui.passwordLineEdit.setEnabled(False)
            self.ui.verifyButton.setEnabled(False)
            self.ui.addVoterButton.setEnabled(False)


    # method for toggle voter UI 
    def ToggleVoterUI(self, show: bool=True) -> None:
        if show:
            self.ui.chooseLabel.show()
            self.ui.demButton.show()
            self.ui.repButton.show()
        else: 
            self.ui.chooseLabel.hide()
            self.ui.demButton.hide()
            self.ui.repButton.hide()


    # method for updating counter label in gui
    def UpdateCounterLabel(self, voteCount: str) -> None:
        self.ui.voteCounter.setText(voteCount)


    # method for updating votes counter labels in gui
    def UpdateVotesCounterLabels(self, demVote: str, repVote: str) -> None:
        self.ui.demVote.setText(demVote + '%')
        self.ui.repVote.setText(repVote + '%')


    # method for updating info label in gui
    @Slot(str)
    def UpdateInfoLabel(self, text: str) -> None:
        self.ui.infoLabel.setText(text)
    

    #method for updating submit info label in gui
    def UpdateSubmitInfoLabel(self, text: str) -> None:
        self.ui.SubmitInfoLabel.setText(text)


    # method for updating id and password
    def UpdateIdPass(self, id: str, password: str) -> None:
        self.ui.idLineEdit.setText(id)
        self.ui.passwordLineEdit.setText(password)


    # method for updating voter info labels in gui
    def UpdateVoterInfo(self, name: str, address: str, city: str, state: str) -> None:
        self.ui.name.setText(name)
        self.ui.address.setText(address)
        self.ui.city.setText(city)
        self.ui.state.setText(state)


    # method for setting submit info values
    def UpdateSubmitInfo(self, firstName: str, lastName: str, address: str, city: str, state: str, id: str, password: str) -> None:
        self.ui.FirstNameLineEdit.setText(firstName)
        self.ui.LastNameLineEdit.setText(lastName)
        self.ui.AddressLineEdit.setText(address)
        self.ui.CityLineEdit.setText(city)
        self.ui.StateLineEdit.setText(state)
        self.ui.IdLineEdit.setText(id)
        self.ui.PasswordLineEdit.setText(password)


    # method to get submit info from gui
    def GetSubmitInfo(self) -> None:
        submitInfo = {
            'firstname': self.ui.FirstNameLineEdit.text(),
            'lastname': self.ui.LastNameLineEdit.text(),
            'address': self.ui.AddressLineEdit.text(),
            'city': self.ui.CityLineEdit.text(),
            'state': self.ui.StateLineEdit.text(),
            'id': self.ui.IdLineEdit.text(),
            'password': self.ui.PasswordLineEdit.text()
        }
        return submitInfo


    # method for showing voter submission page
    def ShowVoterSubmit(self) -> None:
        self.UpdateVoterInfo('', '', '', '')
        self.UpdateIdPass('', '')
        self.UpdateInfoLabel('')
        self.ToggleVoterUI(False)
        self.ui.stackedWidget.setCurrentIndex(1)


    # method for showing main window of app
    def ShowMainWindow(self) -> None:
        self.UpdateSubmitInfo('', '', '', '', '', '', '')
        self.UpdateSubmitInfoLabel('')
        self.ui.stackedWidget.setCurrentIndex(0)


    # method for checking if ip and password are valid
    def CheckIdPassword(self, id: str, password: str) -> bool:
        # get validator result for id and password
        idState = self.idValidator.validate(id, 0)[0]
        passwordState = self.passValidator.validate(password, 0)[0]

        # check that both fields are filled
        if not id or not password:
            self.UpdateInfoLabel('Please fill all required fields.')
            return False

        # check if both ID and password do not matche the regex
        if idState != QValidator.Acceptable and passwordState != QValidator.Acceptable:
            self.UpdateInfoLabel('ID must be 9 digits and password at least 6 characters.')
            return False

        # check if id doesn't matche the regex
        elif idState != QValidator.Acceptable:
            self.UpdateInfoLabel('ID must be exactly 9 digits.')
            return False

        # check if the password doesn't matche the regex
        elif passwordState != QValidator.Acceptable:
            self.UpdateInfoLabel('Password must be at least 6 characters long.')
            return False

        return True


    # method for checking if voter submit info is valid
    def CheckSubmitInfo(self, submitInfo: dict) -> bool:
        errorMessage = '' #represents error message to show voter

        # get validator result for id and password
        idState = self.idValidator.validate(submitInfo['id'], 0)[0]
        passwordState = self.passValidator.validate(submitInfo['password'], 0)[0]
        
        # check that all fields are filled
        if any(not submitInfo[field] for field in ['firstname', 'lastname', 'address', 'city', 'state', 'id', 'password']):
            self.UpdateSubmitInfoLabel('Please fill all required fields.')
            return False

        # check if any field is at least 2 characters long
        if any(len(submitInfo[field].strip().replace(' ', '')) < 2 for field in ['firstname', 'lastname', 'address', 'city', 'state']):
            errorMessage += 'Information fields must be at least 2 characters long.\n'

        # check if both ID and password do not matche the regex
        if idState != QValidator.Acceptable and passwordState != QValidator.Acceptable:
            errorMessage += 'ID must be 9 digits and password at least 6 characters.'

        # check if id doesn't matche the regex
        elif idState != QValidator.Acceptable:
            errorMessage += 'ID must be exactly 9 digits.'

        # check if the password doesn't matche the regex
        elif passwordState != QValidator.Acceptable:
            errorMessage += 'Password must be at least 6 characters long.'
        
        if errorMessage:
            self.UpdateSubmitInfoLabel(errorMessage)
            return False

        return True


    # method for adding a voter to application
    def AddVoterToApp(self) -> bool:
        voterInfo = self.GetSubmitInfo()

        #check if user submmited valid input
        if not self.CheckSubmitInfo(voterInfo):
            return False

        #process the voter information and add him to our database with sha256 for id and pass
        result = SQLHelper.AddVoter(
            self.dbConnection, DH_RSA.ToSHA256(voterInfo['id'], toHex=True), DH_RSA.ToSHA256(voterInfo['password'], toHex=True), 
            voterInfo['firstname'], voterInfo['lastname'],
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
    def VerifyVoter(self) -> bool:
        # clear user info and hide voting ui
        self.UpdateVoterInfo('', '', '', '')
        self.ToggleVoterUI(False)

        # first check that user filled correct info with regex
        if self.CheckIdPassword(self.ui.idLineEdit.text(), self.ui.passwordLineEdit.text()):
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

            # verification was succcesssful, we get sha-256 hashes for id and password
            self.voterId = DH_RSA.ToSHA256(self.ui.idLineEdit.text(), toHex=True) #get given voter id
            voterPassword = DH_RSA.ToSHA256(self.ui.passwordLineEdit.text(), toHex=True) #get given voter password

            # check if voter exists in db, if so mark it as voted and process his vote
            if self.voterId and voterPassword:
                voterInfo = SQLHelper.AuthVoter(self.dbConnection, self.voterId, voterPassword)
                voterStatus = SQLHelper.CheckVoterStatus(self.dbConnection, self.voterId)

                # check if either voter doesn't exists or password is invalid
                if not voterInfo or voterStatus == -1:
                    self.UpdateInfoLabel('Couldn\'t find voter in voting system, check back later...')
                    self.ToggleVerificationUI(True)
                    return False
                # if voter is authenticated and password correct
                elif voterInfo:
                    name = voterInfo['firstname'] + ' ' + voterInfo['lastname']
                    address = voterInfo['address']
                    city, state = voterInfo['city'], voterInfo['state']
                    self.UpdateVoterInfo(name, address, city, state)
                    #if voter already voted we notify him in gui
                    if voterStatus == 1:
                        self.UpdateInfoLabel('Voter is already registered as voted, cannot proceed.')
                        self.ToggleVerificationUI(True)
                        return False
                    # else voter is valid for voting
                    elif voterStatus == 0:
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
    def ProcessVote(self, choice: str) -> bool:
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
                if self.dbConnection and self.voterId:
                    if SQLHelper.SetVoterStatus(self.dbConnection, self.voterId, status=1):
                        # set the vote counter after vote is registered
                        if not self.UpdateVoterCounter() or not self.UpdateResults():
                            self.UpdateInfoLabel('Couldn\'t featch voters information from database.')
                            return False
                        # inform user for registered vote
                        self.UpdateInfoLabel('Vote registered successfully, thank you for your time.')
                        self.ToggleVoterUI(False)
                        return True
                    else:
                        self.UpdateInfoLabel('Couldn\'t process vote, try again later.')
                        self.ToggleVoterUI(False)
                        return False
            else:
                self.UpdateInfoLabel('Couldn\'t process vote, try again later.')
                self.ToggleVoterUI(False)
                return False

        except Exception as e:
            print(f'Main app: Error occurred: {e}.')
            self.UpdateInfoLabel('Couldn\'t process vote, try again later.')
            self.ToggleVoterUI(False)

#--------------------------------------------------------SECURE-VOTE-END--------------------------------------------------------#

#-----------------------------------------------------INIT-PROCESSES-THREAD-----------------------------------------------------#
# thread for initializing centers and ZKP verifier server
class Init_Processes_Thread(QThread):
    # define signals for updating info label and verification UI in gui
    updateInfoLabelSignal: Signal = Signal(str)
    updateVerificationUISignal: Signal = Signal(bool)

    # constructor of processes thread
    def __init__(self, parent: QObject=None) -> None:
        super().__init__(parent)
        self.parent = parent


    # run method for initializing centers and ZKP verifier server
    def run(self) -> None:
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
            print(f'Init_Processes_Thread: Error occurred: {e}.')

#------------------------------------------------------------MAIN---------------------------------------------------------------#

if __name__ == '__main__':
    #check if listening server is running
    if SecureVote.CheckServer():
        print('Another instance is already running.')
        sys.exit(0)

    #initalize listening server for application
    if not SecureVote.InitServer():
        print('Failed to initialize listening server.')
        sys.exit(1)

    #start SecureVote application
    app = QApplication(sys.argv)
    secureVote = SecureVote()
    secureVote.show()

    #execute application and return execution code
    ret = app.exec()
    print('Exiting.')
    sys.exit(ret)

#----------------------------------------------------------MAIN-END-------------------------------------------------------------#