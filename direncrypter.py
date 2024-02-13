import pyAesCrypt
from secrets import token_urlsafe
from os import walk
from os.path import getsize, isfile, basename
from pathlib import Path
from io import BytesIO
from multiprocessing import Pool


def get_all_files_from_dir(dirpath: str):
	return list(Path(dir) / file for dir, _, files in walk(dirpath) for file in files)


class DirEncrypter:
	MAX_FILE_SIZE_MB = 400 * 1024 * 1024
	PROCESS_COUNT = 4

	def __init__(self, dir_for_encrypt):
		self.dir_for_encrypt = dir_for_encrypt
		self.buffersize = 256 * 1024
		self.password = token_urlsafe(16)
		self.all_dir_files = get_all_files_from_dir(self.dir_for_encrypt)

	def generate_key_file(self, key_dir):
		with open(key_dir, 'w') as f:
			f.write(self.password)

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

	def _decrypt_file(self, filepath: str):
		try:
			with open(filepath, 'rb') as fin:
				file_content = BytesIO(fin.read())
			with open(filepath, 'wb') as fout:
				pyAesCrypt.decryptStream(file_content, fout, self.password, self.buffersize)

		except (PermissionError, ValueError) as e:
			print(f'Ошибка расшифровки файла: {filepath}', e)

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
	if not Path(base_dir).exists() or not base_dir or base_dir == '.':
		print('[X] Неверная директория')
		return
	
	encrypter = DirEncrypter(base_dir)
	encrypt_or_decrypt = input('1 - зашифровать директорию | 2 - расшифровать директорию: ')

	match encrypt_or_decrypt:
		case '1':
			key_dir = Path(input('[->] Куда сохранить ключ (Укажите папку): '))
			if not key_dir.exists() or isfile(key_dir):
				print('[X] Неверный путь')
				return
			key_dir = key_dir / Path(basename(base_dir) + '_key')
			encrypter.generate_key_file(key_dir)
			encrypter.encrypt_dir()
			print(f'[V] Ключ находится по адресу {key_dir}')

		case '2':
			key_path = Path(input('[->] Полный путь до ключа: '))
			if not key_path.exists() or not isfile(key_path):
				print('[X] Неверный путь до ключа')
				return
			elif basename(base_dir) + '_key' != basename(key_path):
				print('[X] Вероятно неверный файл')
				return

			with open(key_path, 'r') as f:
				key = f.read()

			key_path.unlink()
			encrypter.password = key
			encrypter.decrypt_dir()
		case _:
			print('[X] Неверный ввод')
			return


if __name__ == '__main__':
	main()