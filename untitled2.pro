#-------------------------------------------------
#
# Project created by QtCreator 2018-04-26T19:59:12
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = untitled2
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        main.cpp \
        mainwindow.cpp \
    select.cpp \
    mythread.cpp \
    filter.cpp \
    attack.cpp

HEADERS += \
        mainwindow.h \
    select.h \
    analyze.h \
    mythread.h \
    filter.h \
    attack.h

FORMS += \
        mainwindow.ui \
    select.ui \
    filter.ui \
    attack.ui

#INCLUDEPATH += C:\WpdPack\Include
#LIBS += -L C:/WpdPack/Lib/*.lib
INCLUDEPATH += ../WpdPack/Include
LIBS += -L ../WpdPack/Lib/*.lib
LIBS += -lWs2_32
DEFINES += WPCAP
DEFINES += HAVE_REMOTE


