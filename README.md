# blue-app-otherdime 
OtherDime : secure private key swapping application

This application demonstrates a Nano S private key swapping application relying on the attestation logic, locking the code logic to the attestation. For more information, you can refer to the following Medium post : https://medium.com/@Ledger/attestation-redux-proving-code-execution-on-the-ledger-platform-fd11ab0f7c19#.nvuut3ubc

To use this application as is, the attestation has to be set to use Ledger as Owner, setting up the attestation as follows on a Nano S  

```
python -m ledgerblue.endorsementSetupLedger --url https://hsmprod.hardwarewallet.com/hsm/process --perso perso_11 --key 1 --endorsement attest_1 --targetId 0x31100002
```

If you plan to use it within your own group, you can modify the OWNER_PUBLIC_KEY field 

Several scripts are available for the most common actions in the py/ directory : 

  * createKey to create a new key, ready to be exchanged

  * getPublicKey to retrieve the public key associated to a created key

  * getStatus to retrieve the status of the application regarding the key provisioning and sealing

  * sign to sign a given hash after unsealing the key following a user confirmation. Unsealing makes the key non exchangeable

  * exchange to exchange a sealed key between a personalized dongle and a non personalization dongle, following user confirmation 

This application is currently usable on Nano S developer firmware 1.2.1 - you can upgrade as follows

```
python -m ledgerblue.updateFirmware --url https://hsmprod.hardwarewallet.com/hsm/process --perso perso_11 --targetId 0x31100002 --firmware nanos_121/upgrade_nanos_osu_1.2.1 --firmwareKey nanos_121/upgrade_nanos_osu_1.2.1_key --apdu

python -m ledgerblue.updateFirmware --url https://hsmprod.hardwarewallet.com/hsm/process --perso perso_11 --targetId 0x31100002 --firmware nanos_121/upgrade_nanos_1.2.1 --firmwareKey nanos_121/upgrade_nanos_1.2.1_key --apdu

```
    
