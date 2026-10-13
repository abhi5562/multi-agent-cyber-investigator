import os
from neo4j import GraphDatabase

class Neo4jClient:
    def __init__(self):
        self._driver = Neo4jClient.get_driver()

    @staticmethod
    def get_driver():
        uri = os.getenv("NEO4J_URI")
        username = os.getenv("NEO4J_USERNAME")
        password = os.getenv("NEO4J_PASSWORD")

        driver = GraphDatabase.driver(uri=uri, auth=(username, password))

        return driver

    def execute_query(self, query, parameters = None):

        def read_records(transaction):
            records = transaction.run(query, parameters)
            return [record.data() for record in records]

        with self._driver.session(database=os.getenv("NEO4J_DATABASE")) as session:
            return session.execute_read(read_records)

    def check_connection(self):
        self._driver.verify_connectivity()

    def close_connection(self):
        self._driver.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close_connection()
