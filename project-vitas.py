import os
import sys
import json
import shutil
import ipfsapi
import base64

import datetime
import maya
from twisted.logger import globalLogPublisher
from umbral.keys import UmbralPublicKey

### NuCypher ###
from nucypher.characters.lawful import Alice, Bob, Ursula
from nucypher.config.characters import AliceConfiguration
from nucypher.characters.lawful import Enrico as Enrico
from nucypher.network.middleware import RestMiddleware

from nucypher.utilities.sandbox.constants import TEMPORARY_DOMAIN

### other
from pprint import pprint

######################
# Boring setup stuff #
######################

r_input = input("Enter IPFS Hash: " )

try:
    SEEDNODE_URI = sys.argv[1]
except IndexError:
    SEEDNODE_URI = "localhost:10151"

##############
# IPFS Setup #
##############

api = ipfsapi.Client(host='https://ipfs.infura.io', port=5001)
ipfs_file = api.object_get(r_input)
ipfs_bytes = json.dumps(ipfs_file).encode('utf-8')

# pprint(ipfs_file)

##############################################
# Ursula, the Untrusted Re-Encryption Proxy  #
##############################################

print("Summoning Ursula")
ursula = Ursula.from_seed_and_stake_info(seed_uri = SEEDNODE_URI,
                                         federated_only = True,
                                         minimum_stake = 0)
##########
# POLICY #
##########

policy_end_datetime = maya.now() + datetime.timedelta(hours = 3)
m, n = 1, 1

##########
# LABELS #
##########

print("Creating labels")
label_A = b"electronic/health/data/A"
label_D = b"electronic/health/data/D"

######################################
# Alice, the Authority of the Policy #
######################################
print("Starting Alice, a patient seeking to be matched to a trial")
ALICE = Alice(network_middleware = RestMiddleware(),
              domains={TEMPORARY_DOMAIN},
              known_nodes=[ursula],
              learn_on_same_thread=True,
              federated_only=True)

##########################
# Alice gets policy keys #
##########################

policy_pubkey_A = ALICE.get_policy_encrypting_key_from_label(label_A)
policy_pubkey_D = ALICE.get_policy_encrypting_key_from_label(label_D)

######################################
# Creating our data consumers/Bobs   #
######################################
print("Starting Bob researchers looking for patients to participate in their trials.")
print("One researcher is malicious, one is honest!")
BOB_A = Bob(known_nodes=[ursula],
          domains={TEMPORARY_DOMAIN},
          network_middleware = RestMiddleware(),
          federated_only=True,
          start_learning_now=True,
          learn_on_same_thread=True)

BOB_B = Bob(known_nodes=[ursula],
          domains={TEMPORARY_DOMAIN},
          network_middleware = RestMiddleware(),
          federated_only=True,
          start_learning_now=True,
          learn_on_same_thread=True)

BOB_D = Bob(known_nodes=[ursula],
          domains={TEMPORARY_DOMAIN},
          network_middleware = RestMiddleware(),
          federated_only=True,
          start_learning_now=True,
          learn_on_same_thread=True)

ALICE.start_learning_loop(now=True)

###########################################
# Creating our policies for data sharing  #
###########################################
print("Alice, our patient, shares her data with researchers A, B, and D. She opts not to share with C because their trial is not relevant to her.")

print("Creating policy for trial A")
policy_A = ALICE.grant(BOB_A,
                     label_A,
                     m=m, n=n,
                     expiration=policy_end_datetime)

assert policy_A.public_key == policy_pubkey_A

print("Creating policy for trial D")
policy_D = ALICE.grant(BOB_D,
                     label_D,
                     m=m, n=n,
                     expiration=policy_end_datetime)

assert policy_D.public_key == policy_pubkey_D

#############################################
# Alice puts her public key down and leaves #
#############################################

alices_pubkey_bytes_saved_for_posterity = bytes(ALICE.stamp)

print("Saying bye to Alice, who is off to receive treatment and is offline.")
del ALICE

##############################################
# Bobs join policies and prepare to get data #
##############################################

print("Honest researcher joins the fray")
BOB_A.join_policy(label_A, alices_pubkey_bytes_saved_for_posterity)
BOB_D.join_policy(label_D, alices_pubkey_bytes_saved_for_posterity)

#####################
# Summoning Enricos #
#####################

enrico_A = Enrico(policy_encrypting_key=policy_pubkey_A)
enrico_D = Enrico(policy_encrypting_key=policy_pubkey_D)
print("Summoned encrypters")
print("")
print("")
print("")

#################################
# Retrieving Alice's public key #
#################################

alice_pubkey_restored_from_ancient_scroll = UmbralPublicKey.from_bytes(alices_pubkey_bytes_saved_for_posterity)

#######################################
# Encrypting and decrypting for bob A #
#######################################

try:
    cipherdata_A, _signature_A = enrico_A.encrypt_message(ipfs_bytes)
    print("Enrico_A encrypted data for Bob_A")
    data_source_public_key_A = bytes(enrico_A.stamp)

    enrico_as_understood_by_bob_A = Enrico.from_public_keys(
        verifying_key=data_source_public_key_A,
        policy_encrypting_key=policy_pubkey_A
    )

    print("Honest researcher is attempting to decrypted")
    decrypted_data_A = BOB_A.retrieve(message_kit=cipherdata_A,
                                        data_source=enrico_as_understood_by_bob_A,
                                        alice_verifying_key=alice_pubkey_restored_from_ancient_scroll,
                                        label=label_A)

    decrypted_data_A_0 = decrypted_data_A[0].decode('utf8').replace('\\"','"')

    # pprint(decrypted_data_A_0)

    print("Honest researcher successfully decrypted!")


except Exception as e: print(e)

try:
    cipherdata_D, _signature_D = enrico_D.encrypt_message(ipfs_bytes)
    print("")
    print("")
    print("")
    print("Encryo_D encrypted data for Bob_D")
    data_source_public_key_D = bytes(enrico_D.stamp)

    enrico_as_understood_by_bob_D = Enrico.from_public_keys(
        verifying_key = data_source_public_key_D,
        policy_encrypting_key = policy_pubkey_D
    )

    print("Attempting honest researcher 2")
    decrypted_data_D = BOB_D.retrieve(message_kit=cipherdata_D,
                                        data_source=enrico_as_understood_by_bob_D,
                                        alice_verifying_key=alice_pubkey_restored_from_ancient_scroll,
                                        label=label_D)
    print("Decrypted by researcher 2")
except Exception as e: print(e)

#######################################
# Malicious C tries to access what he can't #
#######################################


try:
    print("Malicious researcher attempting to decrypt")
    decrypted_data_B = BOB_B.retrieve(message_kit=cipherdata_A,
                                        data_source=enrico_as_understood_by_bob_A,
                                        alice_verifying_key=alice_pubkey_restored_from_ancient_scroll,
                                        label=label_A)
    print("Decrypted by Bob C")
    print("Retrieved: {}".format(decrypted_data_B))
except Exception as e:
    print("")
    print("")
    print("")
    print(e)

    print("Stopped malicious researcher from using the wrong key!")
