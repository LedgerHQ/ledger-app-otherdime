"""
*******************************************************************************
*   OtherDime : Attestation demonstration
*   (c) 2017 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************
"""

from ledgerblue.comm import getDongle
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--apdu", help="Display APDU log", action='store_true')
parser.add_argument("--hash", help="Hash to sign (hexadecimal)")
args = parser.parse_args()

if args.hash == None:
	raise Exception("Hash missing")

args.hash = args.hash.decode('hex')
if len(args.hash) != 32:
	raise Exception("Invalid hash size")

dongle = getDongle(args.apdu)
signature = dongle.exchange("e002000020".decode('hex') + args.hash)
print "Signature " + str(signature).encode('hex')

