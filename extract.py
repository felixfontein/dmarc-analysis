#!/usr/bin/python3
import os
import zipfile
import gzip

import config


configuration = config.load_config()

def process_zip_file(filename, dest):
    message_id, real_filename = filename.split('-', 1)
    with zipfile.ZipFile(filename, mode='r') as f:
        if len(f.namelist()) != 1:
            raise Exception("ZIP archive '{}' has not precisely one file!".format(filename))
        xmlfile = f.namelist()[0]
        if '/' in xmlfile or '\\' in xmlfile:
            raise Exception("ZIP archive '{}' contains a file '{}' in a subfolder!".format(filename, xmlfile))
        fn, ext = os.path.splitext(xmlfile)
        if ext != '.xml':
            raise Exception("ZIP archive '{}' contains a non-XML file '{}'!".format(filename, xmlfile))
        bn = os.path.splitext(os.path.basename(real_filename))[0]
        if fn != bn:
            raise Exception("ZIP archive '{}' contains a XML file called '{}', but it should contain one called '{}'!".format(filename, fn, bn))
        new_filename = '{}-{}'.format(message_id, xmlfile)
        if os.path.exists(os.path.join(dest, new_filename)):
            raise Exception("Destination file '{}' already exists!".format(new_filename))
        member = f.getinfo(xmlfile)
        member.filename = new_filename
        f.extract(member, dest)
    os.unlink(filename)

def process_gzip_file(filename, dest):
    message_id, real_filename = filename.split('-', 1)
    if filename.endswith('.gz'):
        xmlfile = filename[:-len('.gz')]
    else:
        xmlfile = filename[:-len('.gzip')]
    with gzip.open(filename, mode='rb') as f:
        content = f.read()
    if os.path.exists(os.path.join(dest, xmlfile)):
        raise Exception("Destination file '{}' already exists!".format(xmlfile))
    with open(os.path.join(dest, xmlfile), 'wb') as f:
        f.write(content)
    os.unlink(filename)

def process(source, dest):
    for dirpath, _, filenames in os.walk(source):
        for filename in filenames:
            success = False
            try:
                if filename.endswith('.zip'):
                    process_zip_file(os.path.join(dirpath, filename), dest)
                    success = True
                if filename.endswith('.gz') or filename.endswith('.gzip'):
                    process_gzip_file(os.path.join(dirpath, filename), dest)
                    success = True
            except Exception as e:
                print(e)
            if success:
                print('Successfully processed {}.'.format(os.path.join(dirpath, filename)))

source = '.'
dest = 'files/'
process(source, dest)
