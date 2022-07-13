from google.auth import credentials
import pysftp 
import pandas as pd
from google.oauth2 import service_account
from google.cloud import secretmanager
import json
import gnupg
import pandas_gbq
import argparse
import os


# Extract files 
def extractanddecrypt(args):
    
    # Declare varibles specified with arguments

    sftp_credentials=args.sftp_sa #sftp sa to access secret
    file=args.f#regex filename to download
    secret_resource=args.secret_resource #secret resource ID
    pgp_key=args.pgp_key # PGP private key
    passphrase=args.passphrase #PGP passphrase
    

    # Access secrets to retrieve SFTP credentials

    sftp_credentials=args.sftp_sa
    credentials= service_account.Credentials.from_service_account_file(sftp_credentials)
    client=secretmanager.SecretManagerServiceClient(credentials=credentials)
    name=secret_resource
    response=client.access_secret_version(name=name)
    secret=json.loads(response.payload.data.decode("UTF-8"))

    # SFTP credentials 

    cnopts=pysftp.CnOpts()
    cnopts.hostkeys=None
    host=secret['server']
    username=secret['user']
    password=secret['password']

    # Connect to sftp server

    with pysftp.Connection(host=host,username=username,password=password,cnopts=cnopts) as sftp: 
        latest=0
        latestfile=None
        # Get the latest file with regex filename starts with $file and write to local directory
        for fileattr in sftp.listdir_attr():
            if fileattr.filename.startswith(file) and fileattr.st_mtime >latest:
                latest=fileattr.st_mtime
                latestfile=fileattr.filename
        if latestfile is not None:
            sftp.get(latestfile,latestfile)
        sftp.close() # close sftp connection 
        print("Finish downloading file: "+file)

    # Decrypt file with gnupg

    gpg = gnupg.GPG(gpgbinary='/usr/local/bin/gpg')
    gpg.encoding='utf-8'
    key_data=open(pgp_key,'rb').read()
    private_key=gpg.import_keys(key_data)

    # Open and decrypt file
    
    with open(latestfile,'rb') as f:
        decrypted=gpg.decrypt_file(f,passphrase=passphrase,output=latestfile)
    print("ok: ", decrypted.ok)
    
    return(latestfile)

# Load csv to bigquery

def to_bg(args,decrypted_file):
    bg_sa=args.bg_sa # BigQuery sa
    project_id=args.project_id # Project ID
    file=args.f    

    bq_credentials=service_account.Credentials.from_service_account_file(bg_sa)
   # print(decrypted_file)
    path=os.path.join("./",str(decrypted_file))
   # print(path)
    df=pd.read_csv(path,skipfooter=1,skip_blank_lines=True,on_bad_lines='skip',engine='python',encoding='latin-1')
    df.to_gbq(project_id+".etl."+file.replace('ETL_',''),project_id=project_id,if_exists='replace',credentials=bq_credentials)
    
    print("Finish uploading to BigQuery: "+file)


def main():
    parser=argparse.ArgumentParser(description='Simple ETL to extract from SFTP server, decrypt with GNUPG and load to BigQuery with PANDAS_GBQ')
    parser.add_argument("-f",help='specify regex filename pattern',required=True)
    parser.add_argument("-sftp_sa",help='specify path to sftp serve account json file',required=True)
    parser.add_argument("-secret_resource",help='specify secret resource ID',required=True)
    parser.add_argument("-pgp_key",help='specify path to pgp private key',required=True)
    parser.add_argument("-passphrase",help='specify pgp passphrase',required=True)
    parser.add_argument("-bg_sa",help='specify path to BigQuery SA json file',required=True)
    parser.add_argument("-project_id",help='specify project ID',required=True)
    args=parser.parse_args()
    decrypted_file=extractanddecrypt(args)
    to_bg(args,decrypted_file)

if __name__=="__main__":
    main()
