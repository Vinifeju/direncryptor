import pyAesCrypt
from secrets import token_urlsafe
from os import walk
from os.path import getsize
from pathlib import Path
from io import BytesIO
from multiprocessing import Pool


def get_all_files_from_dir(dirpath: str):
    return list(Path(dir) / file for dir, _, files in walk(dirpath) for file in files)


class DirEncrypter:
    MAX_FILE_SIZE_MB = 400 * 1024 * 1024
    PROCESS_COUNT = 5

    def __init__(self, dir_for_encrypt):
        self.dir_for_encrypt = dir_for_encrypt
        self.buffersize = 256 * 1024
        self.password = token_urlsafe(16)
        self.all_dir_files = get_all_files_from_dir(self.dir_for_encrypt)

    def _encrypt_file(self, filepath: str):
        if getsize(filepath) > DirEncrypter.MAX_FILE_SIZE_MB:
            print(f'[X] Файл {filepath} слишком большой')
            return

        try:
            with open(filepath, 'rb') as fin:
                file_content = BytesIO(fin.read())

            with open(filepath, 'wb') as fout:
                pyAesCrypt.encryptStream(file_content, fout, self.password, self.buffersize)

        except (PermissionError, ValueError) as e:
            print(f'Ошибка зашифровки файла: {filepath}', e)
            with open(filepath, 'wb') as fout:
                fout.write(file_content.getvalue())


    def _decrypt_file(self, filepath: str):
        try:
            with open(filepath, 'rb') as fin:
                file_content = BytesIO(fin.read())
            with open(filepath, 'wb') as fout:
                pyAesCrypt.decryptStream(file_content, fout, self.password, self.buffersize)

        except ValueError as e:
            print(f'Ошибка расшифровки файла: {filepath}', e)

            with open(filepath, 'wb') as fout:
                fout.write(file_content.getvalue())



    def encrypt_dir(self):
        print(f'[%] Зашифровка директории: {self.dir_for_encrypt} ...')
        with Pool(DirEncrypter.PROCESS_COUNT) as p:
            p.map(self._encrypt_file, get_all_files_from_dir(self.dir_for_encrypt), chunksize=10)


    def decrypt_dir(self):
        print(f'[%] Расшифровка директории: {self.dir_for_encrypt} ...')
        with Pool(DirEncrypter.PROCESS_COUNT) as p:
            p.map(self._decrypt_file, get_all_files_from_dir(self.dir_for_encrypt), chunksize=10)


def main():
    base_dir = input('[->] Путь до директории: ')
    if not Path(base_dir).exists() or not base_dir:
        print('[X] Неверная директория')
        return
    
    encrypter = DirEncrypter(base_dir)

    # Зашифровка папки
    encrypter.encrypt_dir()

    # Расшифровка папки
    encrypter.decrypt_dir()


if __name__ == '__main__':
    main()
