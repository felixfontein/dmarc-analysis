#!/usr/bin/python3
import email.parser
import email.policy
import os

import imapclient

import config


configuration = config.load_config()

if not configuration.imap_server:
    raise Exception('Please configure imap_server!')
if not configuration.imap_folder:
    raise Exception('Please configure imap_folder!')
if not configuration.imap_user:
    raise Exception('Please configure imap_user!')
imap_password = configuration.get_imap_password()
if not imap_password:
    raise Exception('Please configure imap_password!')

with imapclient.IMAPClient(host=configuration.imap_server) as client:
    client.login(configuration.imap_user, imap_password)

    # Get unread, undeleted messages
    client.select_folder(configuration.imap_folder, readonly=True)
    messages = client.search(['NOT', 'DELETED', 'NOT', 'SEEN'])
    response = client.fetch(messages, ['RFC822'])

    # Prepare marking messages as read
    client.select_folder(configuration.imap_folder, readonly=False)

    parser = email.parser.BytesParser(policy=email.policy.default)
    for message_id, data in response.items():
        # Parse email
        email_message = parser.parsebytes(data[b'RFC822'])
        print('{0}: "{1}", subject: "{2}"'.format(message_id, email_message.get('From'), email_message.get('Subject')))

        # Find attachments
        if not email_message.is_multipart():
            email_message.make_mixed()
        success = False
        for part in email_message.iter_attachments():
            # Found attachment. Write to disk.
            filename = '{0}-{1}'.format(message_id, part.get_filename())
            if os.path.exists(filename):
                print('  WARNING: {0} already exists!'.format(filename))
                continue
            with open(filename, 'wb') as f:
                f.write(part.get_content())
            success = True

        # On success, mark email as read
        if success:
            client.add_flags(message_id, imapclient.SEEN, silent=True)
        else:
            print('  WARNING: cound not extract attachment!')
