# -*- coding: utf-8 -*-
# Copyright (c) 2018 Dunin Ilya.
""" Module to maintain certificate index.txt db """

from csv import reader as csv_reader, writer as csv_writer, QUOTE_NONE
from fcntl import lockf, LOCK_EX, LOCK_NB


SEP = '\t'  # index.txt separator; do not change!
SN_INDEX = 3  # Serial Number column index


class DatabaseError(Exception):
    """ Index.txt database error """
    pass


class IndexDB:
    """ Class for maintain index.txt certificates database """
    def __init__(self, index_db_path):
        """
        Init IndexDB instance
        :param index_db_path: path to index.txt file
        :raise DatabaseBusy: if index.txt already locked
        """
        self._db_path = index_db_path
        self._fd = None
        self._acquire_lock(index_db_path)
        self._data = None

        if not self._fd:
            raise DatabaseError('index.txt database currently locked! Please, try later!')

    def _check_serial_number(self, serial_number):
        """ Check if generated serial number already used
        :param sn: certificate serial number
        :return: True if sn found, else False
        """
        with open(self._db_path) as fd:
            data = csv_reader(fd, delimiter=SEP)
            for row in data:
                if row[SN_INDEX] == str(serial_number):
                    return True
            return False

    def update(self, expiry_date, serial_number, cn):
        """ Update index.txt file, add new cert record. Release index.txt fd
        :param expiry_date: Certificate expiry date
        :param serial_number: Certificate serial_number
        :param cn: Certificate CN
        :raise DatabaseError: if serial number in use
        """
        try:
            if self._check_serial_number(serial_number):
                raise DatabaseError('Serial Number "{}" in use! Try again!'.format(serial_number))
            record = ['V', expiry_date[2:], '', format(serial_number, 'x'), 'unknown', '/CN={}'.format(cn)]
            db_writer = csv_writer(self._fd, delimiter=SEP, quoting=QUOTE_NONE)
            db_writer.writerow(record)
        finally:
            self._release_lock()

    def _acquire_lock(self, index_db_path):
        """ Lock index.txt for read/write """
        fd = None
        try:
            fd = open(index_db_path, 'a')
            lockf(fd, LOCK_EX | LOCK_NB)
            self._fd = fd
        except BlockingIOError:
            if fd:
                fd.close()

    def _release_lock(self):
        """ Release index.txt lock """
        self._fd.close()
