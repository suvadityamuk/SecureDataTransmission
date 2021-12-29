        Functions to implement
                1) Encryption - return encrypted base64 string - done
                2) Decryption - return decrypted normal string out of base64 - done
                3) Key Generation - generate new keys for aes-256  - done
                4) Key Saving into database - save the cipherkey as a b64, rsa-encrypted string in sqlite3 database - done
                5) Key Reading from database - read the cipherkey from sqlite3 db as a b64, rsa-decrypted string and return the keys in usable form for code - done
                6) Key encryption using RSA - encrypt the keys using RSA - done
                7) Key decryption using RSA - decrypt the keys using RSA - done
                8) Store RSA keys in sqlite3 DB - done
                9) Read RSA keys from sqlite3 DB - done
                
                Helper functions:
                
                1) b64 encoder - done/tested
                2) b64 decoder - done/tested
                3) inserting data into db - done/tested
                4) getting data from db - done/tested
                5) delete data from db - done/tested
                6) update data in db - done/tested

                db schema
                - rsa public key = byte array
                - rsa private key = byte array
                - uid primary key = byte array

                dbhelper returns bytearray
                rsahelper uses bytearray to load keys

                b64 -> ciphertext -> main
                main -> ciphertext -> b64


                process of encryption data:
                1)take data
                2)encrypt with aes using key
                3)encrypt aes key with rsa
                4)send encrypted ciphertext and encrypted aes key

                process of decryption data:
                1)take ciphered data
                2)use rsa keys to decipher aes key
                3)use aes key to decipher data
                4)delete aes key from memory

                key storage/retrieval in db:
                1) take uid as input
                2) if uid already exists, return rsa private key
                3) if uid does not exist, create new rsa key pair and store in db against uid
                

                order of completing work

                h1
                h2
                3
                1
                2
                h3
                h4
                4
                5
                6
                7
                8
                9


                // remaining:
                1) append iv to aes key and find way to extract it upon receiving into func
                2) test complete set up, find points of failure and rectify (way too many lmao)
                3) find database resiliency
                4) simple bash cronjob to make copies of db at specific time of week

                PROBLEM:
                1) CREATE TABLE IS NOT BEING INVOKED ANYWHERE, WTF 


