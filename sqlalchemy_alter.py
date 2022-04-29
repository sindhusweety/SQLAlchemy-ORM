#How to Alter with SQLAlchemy?
"""
I found out how to do ** Alter ** with ** SQLAlchemy **, so I'd like to write it as a reminder.

But unfortunately SQLAlchemy doesn't seem to support any special features for running Alter.

In general, change the schema using migration tools such as Alembic and SQLAlchemy-Migrate. To do.

Also, if you really want to change the schema dynamically, Connection.execute () or Use DDL.

Official Documents> Altering Schemas through Migrations http://docs.sqlalchemy.org/en/latest/core/metadata.html#altering-schemas-through-migrations

Operating environment
Mac OS X 10.11.5
Python 3.5.1
MySQL Ver 14.14 Distrib 5.7.11, for osx10.11 (x86_64) using EditLine wrapper
SQLAlchemy 1.1.0
PyMySQL 0.7.4
Sample code
Sample code to add a new column "kana" to the table.

"""

# -*- coding:utf-8 -*-
import sqlalchemy
import sqlalchemy.ext.declarative

Base = sqlalchemy.ext.declarative.declarative_base()

class Student(Base):
    __tablename__ = 'students'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    name = sqlalchemy.Column(sqlalchemy.String(20))

    @staticmethod
    def add_column(engine, column):
        column_name = column.compile(dialect=engine.dialect)
        column_type = column.type.compile(engine.dialect)
        engine.execute('ALTER TABLE %s ADD COLUMN %s %s' % (Student.__tablename__, column_name, column_type))

def main():
    url = 'mysql+pymysql://root:@localhost/test_db?charset=utf8'

    engine = sqlalchemy.create_engine(url, echo=True)

    #Drop the table
    Base.metadata.drop_all(engine)

    #Create table
    Base.metadata.create_all(engine)

    #Add column to table
    column = sqlalchemy.Column('kana', sqlalchemy.String(40), primary_key=False)
    Student.add_column(engine, column)

if __name__ == '__main__':
    main()
