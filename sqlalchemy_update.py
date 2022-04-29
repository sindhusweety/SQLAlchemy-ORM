"""
This time I will write the method of ** Update ** with ** SQLAlchemy **.

Operating environment
Mac OS X 10.11.5
Python 3.5.1
MySQL Ver 14.14 Distrib 5.7.11, for osx10.11 (x86_64) using EditLine wrapper
SQLAlchemy 1.1.0
PyMySQL 0.7.4
Sample code
Update the record of id == 2 (name = "Seiichi Sugino", kana ='Sugi no Seiichi').
"""

# -*- coding:utf-8 -*-
import sqlalchemy
import sqlalchemy.orm
import sqlalchemy.ext.declarative

Base = sqlalchemy.ext.declarative.declarative_base()

class Student(Base):
    __tablename__ = 'students'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    name = sqlalchemy.Column(sqlalchemy.String(20))
    kana = sqlalchemy.Column(sqlalchemy.String(40))

def main():
    url = 'mysql+pymysql://root:@localhost/test_db?charset=utf8'

    engine = sqlalchemy.create_engine(url, echo=True)

    #Create a session
    Session = sqlalchemy.orm.sessionmaker(bind=engine)
    session = Session()

    #Delete all data
    session.query(Student).delete()

    #Register multiple data at once
    session.add_all([
        Student(id=1, name='Yu Ishizaka', kana='Yu Ishizaka'),
        Student(id=2, name='Seiichi Sugino', kana='Sugi no Seiichi'),
        Student(id=3, name='Yuko Kuwata', kana='Yuko Kuwata'),
        Student(id=4, name='Ai Kurihara', kana='Kurihara Ai'),
        ])

    # id==Update 2 data
    student = session.query(Student).filter(Student.id==2).first()
    student.name = 'Hitoshi Sakuma'
    student.kana = 'Sakuma Jin'

    #Output all data in the table
    print_all_students(session)

    #Confirm data
    session.commit()

#A function that outputs all the data in the table
def print_all_students(session):
    students = session.query(Student).all()
    for student in students:
        print('%d, %s %s' % (student.id, student.name, student.kana))

if __name__ == '__main__':
    main()
