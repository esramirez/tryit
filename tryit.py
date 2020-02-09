
import time
import requests
from bs4 import BeautifulSoup
import sys
import smtplib
import pickle
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from email.mime.text import MIMEText
from base64 import urlsafe_b64encode
import logging
import logging.handlers
import threading
import signal

SENDER = "esramirez@gmail.com"
RECIPIENT = "realcacique@protonmail.com"
SUBJECT = "You got an offer in TryIt waiting for you"
CONTENT = "hola puto"

LOG_FILENAME = 'tryit.log'

log_handler = logging.handlers.WatchedFileHandler(LOG_FILENAME)
formatter = logging.Formatter(
        '%(asctime)s tryit [%(process)d]: %(message)s',
        '%b %d %H:%M:%S')
formatter.converter = time.gmtime  # if you want UTC time
log_handler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(log_handler)
logger.setLevel(logging.DEBUG)

class TryitJob(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
 
        # The shutdown_flag is a threading.Event object that
        # indicates whether the thread should be terminated.
        self.shutdown_flag = threading.Event()

    def run(self):
        logging.debug('Job #%s started' % self.ident)
 
        while not self.shutdown_flag.is_set():
            self.tryit()
            time.sleep(0.5)
 
        # ... Clean shutdown code here ...
        logging.debug('Thread #%s stopped' % self.ident)

    def saveCache(self,key="valid", info="N/A"):
        caches = None
        currentDate = info[3]
        if os.path.exists('tryit.pickle'):
            with open('tryit.pickle', 'rb') as cache:
                caches = pickle.load(cache) 
            
        if not caches or caches[3] != currentDate: 
            with open('tryit.pickle', 'wb') as cache:
                pickle.dump(info, cache)
            self.sendSms(info)


    def authenticate1(self):
        form_request_url = "https://tryitsampling.com/authenticate/login" 
        form_type = "POST"
        username_txt_field_id = "login_email"
        password_txt_field_id = "login_password"
        sign_in_btn_id = "submit"  #type
        username = "esramirez@gmail.com"
        password = "password"

        payload = {
        'username': username,
        'password': password
        }
        with requests.Session() as session:
            post = session.post(form_request_url, data=payload)
            logging.debug("????", post)
            r = session.get("http://click.sa.bazaarvoice.com/?qs=c7764e5ada5f859cd2b0ad345f1c21bbdf5b6148b16e230f899a799da4ff116b8613144dc587033dc6f9f7fe190e8058869464414ce29eb0")
            logging.debug(r.text)   #or whatever else you want to do with the request data!

    def sendSms(self,msg):
        sent_from = 'you@gmail.com'
        to = ['realcacique@protonmail.com']
        subject = 'OMG Super Important Message'
        body = msg

        email_text = """\
        From: %s
        To: %s
        Subject: %s

        %s
        """ % (sent_from, ", ".join(to), subject, body)
        
        
    
        raw_msg = self.create_message(SENDER, RECIPIENT, SUBJECT, CONTENT)
        authService = self.gmailService()
        self.send_message(authService,"me",raw_msg)
        logging.debug("Email sent")

 
    def create_message(self,sender, to, subject, message_text):
        """Create a message for an email.

        Args:
            sender: Email address of the sender.
            to: Email address of the receiver.
            subject: The subject of the email message.
            message_text: The text of the email message.

        Returns:
            An object containing a base64url encoded email object.
        """
        message = MIMEText(message_text)
        message['to'] = to
        message['from'] = sender
        message['subject'] = subject
        encoded_message = urlsafe_b64encode(message.as_bytes())
        return {'raw': encoded_message.decode()}


    def send_message(self,service, user_id, message):
        """Send an email message.

        Args:
            service: Authorized Gmail API service instance.
            user_id: User's email address. The special value "me"
            can be used to indicate the authenticated user.
            message: Message to be sent.

        Returns:
            Sent Message.
        """
        try:
            message = (service.users().messages().send(userId=user_id, body=message)
                    .execute())
            logging.debug ('Message Id: %s' % message['id'])
            return message
        except errors.HttpError as error:
            logging.debug ('An error occurred: %s' % error)


    def gmailService(self):
        SCOPES = ['https://www.googleapis.com/auth/gmail.readonly','https://www.googleapis.com/auth/gmail.compose']

        creds = None
        # The file token.pickle stores the user's access and refresh tokens, and is
        # created automatically when the authorization flow completes for the first
        # time.
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)
        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)
        service = build('gmail', 'v1', credentials=creds)
        
        return service

    def tryit(self):
        s = requests.Session() 
        current_offers_table_id = "table-striped"  #table listing the current offers
                                
        authenticated_dest_url = "http://click.sa.bazaarvoice.com/?qs=c7764e5ada5f859cd2b0ad345f1c21bbdf5b6148b16e230f899a799da4ff116b8613144dc587033dc6f9f7fe190e8058869464414ce29eb0"
        #page = requests.get("https://tryitsampling.com/member/dashboard")
        page = s.get(authenticated_dest_url, allow_redirects=False)
        logging.debug("status: " + str(page.status_code))
    
        logging.debug("page redirect url: " + page.url)
        logging.debug("page cookie: " + str(page.cookies))
        logging.debug("status: " + str(page.status_code))
        logging.debug("response history: " + str(page.history))
     
        member_url = page.url
        
        page = s.get(member_url)            #this sends request to redirect url


        
        soup = BeautifulSoup(page.content, 'html.parser')
            
        table_offer = soup.find("table",  class_=current_offers_table_id)
        
        if len(table_offer) > 0:

        
            
            base =  list(table_offer.stripped_strings)
            msg = " ".join(base)
            #msg='Product Name Product ID Requested Shipped Date Reviews|MY ITEM|2/3/2020|2/3/2020'
            listMsg = msg.split("|")
            if len(listMsg) > 1:
            
    
                self.saveCache(info=listMsg)

class ServiceExit(Exception):
    """
    Custom exception which is used to trigger the clean exit
    of all running threads and the main program.
    """
    pass
 
 
def service_shutdown(signum, frame):
    logging.debug('Caught signal %d' % signum)
    raise ServiceExit

def main():

        # Register the signal handlers
    signal.signal(signal.SIGTERM, service_shutdown)
    signal.signal(signal.SIGINT, service_shutdown)
 
    logging.debug('Starting main program')
 
    # Start the job threads
    try:
        j1 = TryitJob()
        j1.start()
        # Keep the main thread running, otherwise signals are ignored.
        while True:
            time.sleep(0.5)
 
    except ServiceExit:
        # Terminate the running threads.
        # Set the shutdown flag on each thread to trigger a clean shutdown of each thread.
        j1.shutdown_flag.set()

        j1.join()

        logging.debug('Exiting main program')       
        

        
              

if __name__ == "__main__":
    main()

    