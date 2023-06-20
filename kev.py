import requests
import psycopg2
import json
import time
from datetime import datetime

# Kev json url 
url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

# Pobieranie danych JSON z pliku z sieci
def handle_kev(url):

	response = requests.get(url)
	data = response.json()
	index = 1
	vulnerabilities =  (data['vulnerabilities'])

	try:
		connection = psycopg2.connect(user='postgres',
										password='ZKApUMahTLoHyqkMvJovBpyvw2KWQe',
										host='localhost',
										port='5432',
										database='vulnmapp')

		cursor = connection.cursor())
		drop_table = """DROP TABLE kev"""
		create_table = """
		
CREATE TABLE public.kev
(
    id bigint NOT NULL,
    "cveID" text NOT NULL,
    "vendorProject" text,
    product text,
    "vulnerabilityName" text,
    "dateAdded" text,
    "shortDescription" text,
    "requiredAction" text,
    "dueDate" text,
    notes text,
    PRIMARY KEY (id)
);

ALTER TABLE IF EXISTS public.kev
    OWNER to postgres;
		"""
		cursor.execute(drop_table)
		# print("Drop bazy udany")
		time.sleep(2)
		# print("Tworzenie bazy na nowo...")
		cursor.execute(create_table)
		# print("Tabela utworzona poprawnie")
		time.sleep(2)

		for x in vulnerabilities:

			cveID = x['cveID']
			vendorProject = x['vendorProject']
			product = x['product']
			vulnerabilityName = x['vulnerabilityName']
			dateAdded = x['dateAdded']
			shortDescription = x['shortDescription']
			requiredAction = x['requiredAction']
			dueDate = x['dueDate']
			notes = x['notes']

			postgres_insert_query = """ 
			INSERT INTO kev (id, "cveID", "vendorProject", product, "vulnerabilityName", "dateAdded", "shortDescription", "requiredAction", "dueDate", notes) 
			VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""

			record_to_insert = (index, cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, notes)

			cursor.execute(postgres_insert_query, record_to_insert)
			connection.commit()
			# print("Record inserted successfully into kev tabel")
			index = index + 1
			
	except(Exception, psycopg2.Error) as error:
		print("Failed to insert record into mobile table", error)
	
	finally:
		# closing databse connection
		if connection:
			cursor.close()
			connection.close()
			# print("PostgreSQL connection is closed")
	

	with open('kev_log.txt', 'a') as f:
		now = datetime.now()
		current_time = now.strftime("%H:%M:%S")
		f.write('\n' + current_time + ' Baza danych KEV zostala zaktualizowana')


handle_kev(url)