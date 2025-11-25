# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'SecureVote.ui'
##
## Created by: Qt User Interface Compiler version 6.9.0
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QApplication, QFormLayout, QFrame, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QPushButton,
    QSizePolicy, QSpacerItem, QStackedWidget, QVBoxLayout,
    QWidget)

class Ui_SecureVote(object):
    def setupUi(self, SecureVote):
        if not SecureVote.objectName():
            SecureVote.setObjectName(u"SecureVote")
        SecureVote.resize(1320, 870)
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(SecureVote.sizePolicy().hasHeightForWidth())
        SecureVote.setSizePolicy(sizePolicy)
        SecureVote.setMinimumSize(QSize(1320, 870))
        SecureVote.setMaximumSize(QSize(1320, 870))
        font = QFont()
        font.setFamilies([u"Arial"])
        font.setPointSize(11)
        SecureVote.setFont(font)
        SecureVote.setStyleSheet(u"QWidget {\n"
"    background-color: rgba(68, 70, 84, 255);\n"
"}")
        self.centralwidget = QWidget(SecureVote)
        self.centralwidget.setObjectName(u"centralwidget")
        self.frame = QFrame(self.centralwidget)
        self.frame.setObjectName(u"frame")
        self.frame.setGeometry(QRect(-10, -10, 1341, 91))
        self.frame.setStyleSheet(u"QFrame {\n"
"   background-color:  rgba(32,33,35,255);\n"
"}\n"
"")
        self.frame.setFrameShape(QFrame.Shape.StyledPanel)
        self.frame.setFrameShadow(QFrame.Shadow.Raised)
        self.horizontalFrame = QFrame(self.frame)
        self.horizontalFrame.setObjectName(u"horizontalFrame")
        self.horizontalFrame.setGeometry(QRect(20, 10, 1141, 80))
        self.horizontalFrame.setStyleSheet(u"QFrame {\n"
"   background-color:  rgba(32,33,35,255);\n"
"}")
        self.horizontalLayout = QHBoxLayout(self.horizontalFrame)
        self.horizontalLayout.setSpacing(2)
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.voteCounterLabel = QLabel(self.horizontalFrame)
        self.voteCounterLabel.setObjectName(u"voteCounterLabel")
        self.voteCounterLabel.setMinimumSize(QSize(170, 0))
        self.voteCounterLabel.setMaximumSize(QSize(170, 16777215))
        font1 = QFont()
        font1.setFamilies([u"Arial"])
        font1.setPointSize(14)
        font1.setBold(True)
        font1.setItalic(False)
        self.voteCounterLabel.setFont(font1)
        self.voteCounterLabel.setStyleSheet(u"QLabel {\n"
"       background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.horizontalLayout.addWidget(self.voteCounterLabel)

        self.voteCounter = QLabel(self.horizontalFrame)
        self.voteCounter.setObjectName(u"voteCounter")
        self.voteCounter.setFont(font1)
        self.voteCounter.setStyleSheet(u"QLabel {\n"
"      background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.horizontalLayout.addWidget(self.voteCounter)

        self.horizontalSpacer = QSpacerItem(24, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout.addItem(self.horizontalSpacer)

        self.topLabel = QLabel(self.horizontalFrame)
        self.topLabel.setObjectName(u"topLabel")
        font2 = QFont()
        font2.setFamilies([u"Arial"])
        font2.setPointSize(22)
        font2.setBold(True)
        font2.setItalic(True)
        self.topLabel.setFont(font2)
        self.topLabel.setStyleSheet(u"QLabel {\n"
"       background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.horizontalLayout.addWidget(self.topLabel)

        self.horizontalSpacer_2 = QSpacerItem(20, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout.addItem(self.horizontalSpacer_2)

        self.stackedWidget = QStackedWidget(self.centralwidget)
        self.stackedWidget.setObjectName(u"stackedWidget")
        self.stackedWidget.setGeometry(QRect(10, 90, 1301, 761))
        self.page1 = QWidget()
        self.page1.setObjectName(u"page1")
        self.addVoterButton = QPushButton(self.page1)
        self.addVoterButton.setObjectName(u"addVoterButton")
        self.addVoterButton.setGeometry(QRect(1140, 30, 141, 43))
        sizePolicy1 = QSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        sizePolicy1.setHorizontalStretch(0)
        sizePolicy1.setVerticalStretch(0)
        sizePolicy1.setHeightForWidth(self.addVoterButton.sizePolicy().hasHeightForWidth())
        self.addVoterButton.setSizePolicy(sizePolicy1)
        self.addVoterButton.setMinimumSize(QSize(141, 43))
        self.addVoterButton.setMaximumSize(QSize(141, 43))
        font3 = QFont()
        font3.setFamilies([u"Arial"])
        font3.setPointSize(12)
        font3.setBold(True)
        self.addVoterButton.setFont(font3)
        self.addVoterButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.addVoterButton.setStyleSheet(u"QPushButton {\n"
"    background-color: rgba(32,33,35,255);\n"
"	color: rgb(245,245,245);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"   background-color: rgb(87, 89, 101);\n"
"	color: white;\n"
"    border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"   background-color: rgb(177, 185, 187);\n"
"	color: white;\n"
"}")
        self.verticalLayoutWidget = QWidget(self.page1)
        self.verticalLayoutWidget.setObjectName(u"verticalLayoutWidget")
        self.verticalLayoutWidget.setGeometry(QRect(220, 20, 861, 711))
        self.verticalLayout_4 = QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout_4.setObjectName(u"verticalLayout_4")
        self.verticalLayout_4.setContentsMargins(0, 0, 0, 0)
        self.infoFrame = QFrame(self.verticalLayoutWidget)
        self.infoFrame.setObjectName(u"infoFrame")
        self.infoFrame.setMaximumSize(QSize(861, 251))
        self.infoFrame.setStyleSheet(u"#infoFrame {\n"
"   background-color: rgba(46, 47, 56, 0.8);\n"
"   border-radius: 15px;\n"
"   border-style: outset;\n"
"   border-width: 2px;\n"
"   border-radius: 15px;\n"
"   border-color: black;\n"
"   padding: 4px;\n"
"}\n"
"")
        self.infoFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.infoFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.infoVerticalFrame = QFrame(self.infoFrame)
        self.infoVerticalFrame.setObjectName(u"infoVerticalFrame")
        self.infoVerticalFrame.setGeometry(QRect(0, 0, 861, 241))
        self.infoVerticalFrame.setMinimumSize(QSize(861, 241))
        self.infoVerticalFrame.setMaximumSize(QSize(861, 241))
        self.infoVerticalFrame.setStyleSheet(u"#infoVerticalFrame {\n"
"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")
        self.verticalLayout_2 = QVBoxLayout(self.infoVerticalFrame)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.verticalLayout_2.setContentsMargins(6, 6, 6, 6)
        self.horizontalWidget_9 = QWidget(self.infoVerticalFrame)
        self.horizontalWidget_9.setObjectName(u"horizontalWidget_9")
        self.horizontalWidget_9.setMinimumSize(QSize(861, 41))
        self.horizontalWidget_9.setMaximumSize(QSize(861, 41))
        self.horizontalWidget_9.setStyleSheet(u"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;")
        self.horizontalLayout_12 = QHBoxLayout(self.horizontalWidget_9)
        self.horizontalLayout_12.setObjectName(u"horizontalLayout_12")
        self.horizontalSpacer_31 = QSpacerItem(120, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_12.addItem(self.horizontalSpacer_31)

        self.currentResultLabel = QLabel(self.horizontalWidget_9)
        self.currentResultLabel.setObjectName(u"currentResultLabel")
        self.currentResultLabel.setMaximumSize(QSize(181, 51))
        font4 = QFont()
        font4.setFamilies([u"Arial"])
        font4.setPointSize(16)
        font4.setBold(True)
        font4.setItalic(False)
        self.currentResultLabel.setFont(font4)
        self.currentResultLabel.setStyleSheet(u"QLabel {\n"
"   color: rgb(245,245,245);\n"
"}")
        self.currentResultLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.horizontalLayout_12.addWidget(self.currentResultLabel)

        self.horizontalSpacer_32 = QSpacerItem(120, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_12.addItem(self.horizontalSpacer_32)


        self.verticalLayout_2.addWidget(self.horizontalWidget_9)

        self.horizontalFrame_3 = QFrame(self.infoVerticalFrame)
        self.horizontalFrame_3.setObjectName(u"horizontalFrame_3")
        self.horizontalFrame_3.setMinimumSize(QSize(861, 0))
        self.horizontalFrame_3.setMaximumSize(QSize(861, 51))
        self.horizontalFrame_3.setStyleSheet(u"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;")
        self.horizontalLayout_13 = QHBoxLayout(self.horizontalFrame_3)
        self.horizontalLayout_13.setObjectName(u"horizontalLayout_13")
        self.horizontalSpacer_33 = QSpacerItem(120, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_13.addItem(self.horizontalSpacer_33)

        self.demLabel = QLabel(self.horizontalFrame_3)
        self.demLabel.setObjectName(u"demLabel")
        self.demLabel.setMinimumSize(QSize(150, 0))
        self.demLabel.setMaximumSize(QSize(150, 31))
        self.demLabel.setFont(font1)
        self.demLabel.setStyleSheet(u"QLabel {\n"
"    background-color: none;\n"
"   color: #0074D9;\n"
"   border: none;\n"
"}")

        self.horizontalLayout_13.addWidget(self.demLabel)

        self.demVote = QLabel(self.horizontalFrame_3)
        self.demVote.setObjectName(u"demVote")
        self.demVote.setMinimumSize(QSize(51, 0))
        self.demVote.setMaximumSize(QSize(51, 31))
        self.demVote.setFont(font1)
        self.demVote.setStyleSheet(u"QLabel {\n"
"    background-color: none;\n"
"   color: #0074D9;\n"
"   border: none;\n"
"}")

        self.horizontalLayout_13.addWidget(self.demVote)

        self.horizontalSpacer_34 = QSpacerItem(150, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_13.addItem(self.horizontalSpacer_34)

        self.repLabel = QLabel(self.horizontalFrame_3)
        self.repLabel.setObjectName(u"repLabel")
        self.repLabel.setMinimumSize(QSize(165, 0))
        self.repLabel.setMaximumSize(QSize(165, 31))
        self.repLabel.setFont(font1)
        self.repLabel.setStyleSheet(u"QLabel {\n"
"    background-color: none;\n"
"   color:  #FF4136;\n"
"   border: none;\n"
"}")

        self.horizontalLayout_13.addWidget(self.repLabel)

        self.repVote = QLabel(self.horizontalFrame_3)
        self.repVote.setObjectName(u"repVote")
        self.repVote.setMinimumSize(QSize(51, 0))
        self.repVote.setMaximumSize(QSize(51, 31))
        self.repVote.setFont(font1)
        self.repVote.setStyleSheet(u"QLabel {\n"
"    background-color: none;\n"
"   color: #FF4136;\n"
"   border: none;\n"
"}")

        self.horizontalLayout_13.addWidget(self.repVote)

        self.horizontalSpacer_37 = QSpacerItem(120, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_13.addItem(self.horizontalSpacer_37)


        self.verticalLayout_2.addWidget(self.horizontalFrame_3)

        self.horizontalWidget_5 = QWidget(self.infoVerticalFrame)
        self.horizontalWidget_5.setObjectName(u"horizontalWidget_5")
        self.horizontalWidget_5.setMinimumSize(QSize(861, 41))
        self.horizontalWidget_5.setMaximumSize(QSize(861, 41))
        self.horizontalWidget_5.setStyleSheet(u"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;")
        self.horizontalLayout_8 = QHBoxLayout(self.horizontalWidget_5)
        self.horizontalLayout_8.setObjectName(u"horizontalLayout_8")
        self.horizontalSpacer_14 = QSpacerItem(120, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_8.addItem(self.horizontalSpacer_14)

        self.voterLabel = QLabel(self.horizontalWidget_5)
        self.voterLabel.setObjectName(u"voterLabel")
        self.voterLabel.setMaximumSize(QSize(191, 51))
        self.voterLabel.setFont(font4)
        self.voterLabel.setStyleSheet(u"QLabel {\n"
"   color: rgb(245,245,245);\n"
"}")
        self.voterLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.horizontalLayout_8.addWidget(self.voterLabel)

        self.horizontalSpacer_15 = QSpacerItem(120, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_8.addItem(self.horizontalSpacer_15)


        self.verticalLayout_2.addWidget(self.horizontalWidget_5)

        self.horizontalFrame_2 = QFrame(self.infoVerticalFrame)
        self.horizontalFrame_2.setObjectName(u"horizontalFrame_2")
        self.horizontalFrame_2.setMinimumSize(QSize(861, 0))
        self.horizontalFrame_2.setMaximumSize(QSize(861, 51))
        self.horizontalFrame_2.setStyleSheet(u"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;")
        self.horizontalLayout_7 = QHBoxLayout(self.horizontalFrame_2)
        self.horizontalLayout_7.setObjectName(u"horizontalLayout_7")
        self.horizontalSpacer_22 = QSpacerItem(20, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_7.addItem(self.horizontalSpacer_22)

        self.nameLabel = QLabel(self.horizontalFrame_2)
        self.nameLabel.setObjectName(u"nameLabel")
        self.nameLabel.setMaximumSize(QSize(51, 31))
        font5 = QFont()
        font5.setFamilies([u"Arial"])
        font5.setPointSize(12)
        font5.setBold(True)
        font5.setItalic(False)
        self.nameLabel.setFont(font5)
        self.nameLabel.setStyleSheet(u"QLabel {\n"
"    background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.horizontalLayout_7.addWidget(self.nameLabel)

        self.name = QLabel(self.horizontalFrame_2)
        self.name.setObjectName(u"name")
        self.name.setMinimumSize(QSize(145, 0))
        self.name.setMaximumSize(QSize(170, 31))
        self.name.setFont(font5)
        self.name.setStyleSheet(u"QLabel {\n"
"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.horizontalLayout_7.addWidget(self.name)

        self.horizontalSpacer_18 = QSpacerItem(40, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_7.addItem(self.horizontalSpacer_18)

        self.addressLabel = QLabel(self.horizontalFrame_2)
        self.addressLabel.setObjectName(u"addressLabel")
        self.addressLabel.setMaximumSize(QSize(72, 31))
        self.addressLabel.setFont(font5)
        self.addressLabel.setStyleSheet(u"QLabel {\n"
"    background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.horizontalLayout_7.addWidget(self.addressLabel)

        self.address = QLabel(self.horizontalFrame_2)
        self.address.setObjectName(u"address")
        self.address.setMinimumSize(QSize(145, 31))
        self.address.setMaximumSize(QSize(145, 31))
        self.address.setFont(font5)
        self.address.setStyleSheet(u"QLabel {\n"
"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.horizontalLayout_7.addWidget(self.address)

        self.horizontalSpacer_19 = QSpacerItem(40, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_7.addItem(self.horizontalSpacer_19)

        self.cityLabel = QLabel(self.horizontalFrame_2)
        self.cityLabel.setObjectName(u"cityLabel")
        self.cityLabel.setMaximumSize(QSize(38, 31))
        self.cityLabel.setFont(font5)
        self.cityLabel.setStyleSheet(u"QLabel {\n"
"    background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.horizontalLayout_7.addWidget(self.cityLabel)

        self.city = QLabel(self.horizontalFrame_2)
        self.city.setObjectName(u"city")
        self.city.setMinimumSize(QSize(145, 0))
        self.city.setMaximumSize(QSize(145, 31))
        self.city.setFont(font5)
        self.city.setStyleSheet(u"QLabel {\n"
"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.horizontalLayout_7.addWidget(self.city)

        self.horizontalSpacer_20 = QSpacerItem(20, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_7.addItem(self.horizontalSpacer_20)

        self.stateLabel = QLabel(self.horizontalFrame_2)
        self.stateLabel.setObjectName(u"stateLabel")
        self.stateLabel.setMaximumSize(QSize(46, 31))
        self.stateLabel.setFont(font5)
        self.stateLabel.setStyleSheet(u"QLabel {\n"
"    background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.horizontalLayout_7.addWidget(self.stateLabel)

        self.state = QLabel(self.horizontalFrame_2)
        self.state.setObjectName(u"state")
        self.state.setMinimumSize(QSize(145, 0))
        self.state.setMaximumSize(QSize(145, 31))
        self.state.setFont(font5)
        self.state.setStyleSheet(u"QLabel {\n"
"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.horizontalLayout_7.addWidget(self.state)

        self.horizontalSpacer_21 = QSpacerItem(20, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_7.addItem(self.horizontalSpacer_21)


        self.verticalLayout_2.addWidget(self.horizontalFrame_2)


        self.verticalLayout_4.addWidget(self.infoFrame)

        self.horizontalWidget_6 = QWidget(self.verticalLayoutWidget)
        self.horizontalWidget_6.setObjectName(u"horizontalWidget_6")
        self.horizontalWidget_6.setMaximumSize(QSize(861, 41))
        self.horizontalWidget_6.setStyleSheet(u"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;")
        self.horizontalLayout_9 = QHBoxLayout(self.horizontalWidget_6)
        self.horizontalLayout_9.setObjectName(u"horizontalLayout_9")
        self.horizontalSpacer_16 = QSpacerItem(120, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_9.addItem(self.horizontalSpacer_16)

        self.infoLabel = QLabel(self.horizontalWidget_6)
        self.infoLabel.setObjectName(u"infoLabel")
        self.infoLabel.setMaximumSize(QSize(500, 51))
        font6 = QFont()
        font6.setFamilies([u"Arial"])
        font6.setPointSize(13)
        font6.setBold(True)
        font6.setItalic(True)
        self.infoLabel.setFont(font6)
        self.infoLabel.setStyleSheet(u"QLabel {\n"
"   color: rgb(245,245,245);\n"
"}")
        self.infoLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.horizontalLayout_9.addWidget(self.infoLabel)

        self.horizontalSpacer_17 = QSpacerItem(120, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_9.addItem(self.horizontalSpacer_17)


        self.verticalLayout_4.addWidget(self.horizontalWidget_6)

        self.voterFrame = QFrame(self.verticalLayoutWidget)
        self.voterFrame.setObjectName(u"voterFrame")
        self.voterFrame.setMaximumSize(QSize(861, 381))
        self.voterFrame.setStyleSheet(u"#voterFrame {\n"
"   background-color: rgba(46, 47, 56, 0.8);\n"
"   border-radius: 15px;\n"
"   border-style: outset;\n"
"   border-width: 2px;\n"
"   border-radius: 15px;\n"
"   border-color: black;\n"
"   padding: 4px;\n"
"}\n"
"")
        self.voterFrame.setFrameShape(QFrame.Shape.StyledPanel)
        self.voterFrame.setFrameShadow(QFrame.Shadow.Raised)
        self.voterVerticalFrame = QFrame(self.voterFrame)
        self.voterVerticalFrame.setObjectName(u"voterVerticalFrame")
        self.voterVerticalFrame.setGeometry(QRect(0, 0, 861, 381))
        self.voterVerticalFrame.setMinimumSize(QSize(861, 381))
        self.voterVerticalFrame.setMaximumSize(QSize(861, 381))
        self.voterVerticalFrame.setStyleSheet(u"#voterVerticalFrame {\n"
"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}\n"
"")
        self.verticalLayout = QVBoxLayout(self.voterVerticalFrame)
        self.verticalLayout.setSpacing(4)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.horizontalWidget_4 = QWidget(self.voterVerticalFrame)
        self.horizontalWidget_4.setObjectName(u"horizontalWidget_4")
        sizePolicy2 = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        sizePolicy2.setHorizontalStretch(0)
        sizePolicy2.setVerticalStretch(0)
        sizePolicy2.setHeightForWidth(self.horizontalWidget_4.sizePolicy().hasHeightForWidth())
        self.horizontalWidget_4.setSizePolicy(sizePolicy2)
        self.horizontalWidget_4.setMaximumSize(QSize(861, 41))
        self.horizontalWidget_4.setStyleSheet(u"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;")
        self.horizontalLayout_5 = QHBoxLayout(self.horizontalWidget_4)
        self.horizontalLayout_5.setObjectName(u"horizontalLayout_5")
        self.horizontalSpacer_12 = QSpacerItem(120, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_5.addItem(self.horizontalSpacer_12)

        self.verificationLabel = QLabel(self.horizontalWidget_4)
        self.verificationLabel.setObjectName(u"verificationLabel")
        self.verificationLabel.setMaximumSize(QSize(191, 51))
        self.verificationLabel.setFont(font4)
        self.verificationLabel.setStyleSheet(u"QLabel {\n"
"   color: rgb(245,245,245);\n"
"}")
        self.verificationLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.horizontalLayout_5.addWidget(self.verificationLabel)

        self.horizontalSpacer_13 = QSpacerItem(120, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_5.addItem(self.horizontalSpacer_13)


        self.verticalLayout.addWidget(self.horizontalWidget_4)

        self.horizontalWidget_3 = QWidget(self.voterVerticalFrame)
        self.horizontalWidget_3.setObjectName(u"horizontalWidget_3")
        self.horizontalWidget_3.setMinimumSize(QSize(0, 50))
        self.horizontalWidget_3.setMaximumSize(QSize(861, 50))
        self.horizontalWidget_3.setStyleSheet(u"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;")
        self.horizontalLayout_3 = QHBoxLayout(self.horizontalWidget_3)
        self.horizontalLayout_3.setObjectName(u"horizontalLayout_3")
        self.horizontalSpacer_24 = QSpacerItem(120, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_3.addItem(self.horizontalSpacer_24)

        self.idLabel = QLabel(self.horizontalWidget_3)
        self.idLabel.setObjectName(u"idLabel")
        self.idLabel.setMinimumSize(QSize(66, 41))
        self.idLabel.setMaximumSize(QSize(66, 41))
        self.idLabel.setFont(font5)
        self.idLabel.setStyleSheet(u"QLabel {\n"
"   color: rgb(245,245,245);\n"
"}")

        self.horizontalLayout_3.addWidget(self.idLabel)

        self.idLineEdit = QLineEdit(self.horizontalWidget_3)
        self.idLineEdit.setObjectName(u"idLineEdit")
        sizePolicy1.setHeightForWidth(self.idLineEdit.sizePolicy().hasHeightForWidth())
        self.idLineEdit.setSizePolicy(sizePolicy1)
        self.idLineEdit.setMinimumSize(QSize(170, 41))
        self.idLineEdit.setMaximumSize(QSize(170, 41))
        font7 = QFont()
        font7.setFamilies([u"Arial"])
        font7.setPointSize(12)
        self.idLineEdit.setFont(font7)
        self.idLineEdit.setStyleSheet(u"QLineEdit {\n"
"    background-color: rgba(32,33,35,255);\n"
"	color: rgb(245,245,245);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}")
        self.idLineEdit.setMaxLength(9)

        self.horizontalLayout_3.addWidget(self.idLineEdit)

        self.horizontalSpacer_23 = QSpacerItem(50, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_3.addItem(self.horizontalSpacer_23)

        self.passwordLabel = QLabel(self.horizontalWidget_3)
        self.passwordLabel.setObjectName(u"passwordLabel")
        self.passwordLabel.setMinimumSize(QSize(86, 41))
        self.passwordLabel.setMaximumSize(QSize(86, 41))
        self.passwordLabel.setFont(font5)
        self.passwordLabel.setStyleSheet(u"QLabel {\n"
"   color: rgb(245,245,245);\n"
"}")

        self.horizontalLayout_3.addWidget(self.passwordLabel)

        self.passwordLineEdit = QLineEdit(self.horizontalWidget_3)
        self.passwordLineEdit.setObjectName(u"passwordLineEdit")
        sizePolicy1.setHeightForWidth(self.passwordLineEdit.sizePolicy().hasHeightForWidth())
        self.passwordLineEdit.setSizePolicy(sizePolicy1)
        self.passwordLineEdit.setMinimumSize(QSize(170, 41))
        self.passwordLineEdit.setMaximumSize(QSize(170, 41))
        self.passwordLineEdit.setFont(font7)
        self.passwordLineEdit.setStyleSheet(u"QLineEdit {\n"
"    background-color: rgba(32,33,35,255);\n"
"	color: rgb(245,245,245);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}")
        self.passwordLineEdit.setMaxLength(16)

        self.horizontalLayout_3.addWidget(self.passwordLineEdit)

        self.horizontalSpacer_8 = QSpacerItem(120, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_3.addItem(self.horizontalSpacer_8)


        self.verticalLayout.addWidget(self.horizontalWidget_3)

        self.verticalSpacer = QSpacerItem(20, 9, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)

        self.verticalLayout.addItem(self.verticalSpacer)

        self.horizontalWidget_7 = QWidget(self.voterVerticalFrame)
        self.horizontalWidget_7.setObjectName(u"horizontalWidget_7")
        self.horizontalWidget_7.setMinimumSize(QSize(0, 60))
        self.horizontalWidget_7.setMaximumSize(QSize(861, 60))
        self.horizontalWidget_7.setStyleSheet(u"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;")
        self.horizontalLayout_6 = QHBoxLayout(self.horizontalWidget_7)
        self.horizontalLayout_6.setObjectName(u"horizontalLayout_6")
        self.horizontalSpacer_25 = QSpacerItem(120, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_6.addItem(self.horizontalSpacer_25)

        self.verifyButton = QPushButton(self.horizontalWidget_7)
        self.verifyButton.setObjectName(u"verifyButton")
        sizePolicy1.setHeightForWidth(self.verifyButton.sizePolicy().hasHeightForWidth())
        self.verifyButton.setSizePolicy(sizePolicy1)
        self.verifyButton.setMinimumSize(QSize(141, 43))
        self.verifyButton.setMaximumSize(QSize(141, 43))
        self.verifyButton.setFont(font3)
        self.verifyButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.verifyButton.setStyleSheet(u"QPushButton {\n"
"    background-color: rgba(32,33,35,255);\n"
"	color: rgb(245,245,245);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"   background-color: rgb(87, 89, 101);\n"
"	color: white;\n"
"    border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"   background-color: rgb(177, 185, 187);\n"
"	color: white;\n"
"}")

        self.horizontalLayout_6.addWidget(self.verifyButton)

        self.horizontalSpacer_9 = QSpacerItem(120, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_6.addItem(self.horizontalSpacer_9)


        self.verticalLayout.addWidget(self.horizontalWidget_7)

        self.verticalSpacer_2 = QSpacerItem(20, 9, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)

        self.verticalLayout.addItem(self.verticalSpacer_2)

        self.horizontalWidget_2 = QWidget(self.voterVerticalFrame)
        self.horizontalWidget_2.setObjectName(u"horizontalWidget_2")
        self.horizontalWidget_2.setMaximumSize(QSize(861, 41))
        self.horizontalWidget_2.setStyleSheet(u"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;")
        self.horizontalLayout_4 = QHBoxLayout(self.horizontalWidget_2)
        self.horizontalLayout_4.setObjectName(u"horizontalLayout_4")
        self.horizontalSpacer_11 = QSpacerItem(120, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_4.addItem(self.horizontalSpacer_11)

        self.chooseLabel = QLabel(self.horizontalWidget_2)
        self.chooseLabel.setObjectName(u"chooseLabel")
        self.chooseLabel.setMaximumSize(QSize(261, 51))
        self.chooseLabel.setFont(font4)
        self.chooseLabel.setStyleSheet(u"QLabel {\n"
"   color: rgb(245,245,245);\n"
"}")
        self.chooseLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.horizontalLayout_4.addWidget(self.chooseLabel)

        self.horizontalSpacer_10 = QSpacerItem(120, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_4.addItem(self.horizontalSpacer_10)


        self.verticalLayout.addWidget(self.horizontalWidget_2)

        self.horizontalWidget_8 = QWidget(self.voterVerticalFrame)
        self.horizontalWidget_8.setObjectName(u"horizontalWidget_8")
        self.horizontalWidget_8.setMaximumSize(QSize(861, 61))
        self.horizontalWidget_8.setStyleSheet(u"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;")
        self.horizontalLayout_2 = QHBoxLayout(self.horizontalWidget_8)
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.horizontalSpacer_6 = QSpacerItem(50, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_2.addItem(self.horizontalSpacer_6)

        self.demButton = QPushButton(self.horizontalWidget_8)
        self.demButton.setObjectName(u"demButton")
        sizePolicy1.setHeightForWidth(self.demButton.sizePolicy().hasHeightForWidth())
        self.demButton.setSizePolicy(sizePolicy1)
        self.demButton.setMaximumSize(QSize(141, 43))
        self.demButton.setFont(font3)
        self.demButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.demButton.setStyleSheet(u"QPushButton {\n"
"    background-color:#0074D9;\n"
"	color: rgb(245,245,245);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"   background-color: #33A1D9;\n"
"	color: white;\n"
"    border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"   background-color: rgb(177, 185, 187);\n"
"	color: white;\n"
"}")

        self.horizontalLayout_2.addWidget(self.demButton)

        self.horizontalSpacer_4 = QSpacerItem(15, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_2.addItem(self.horizontalSpacer_4)

        self.repButton = QPushButton(self.horizontalWidget_8)
        self.repButton.setObjectName(u"repButton")
        self.repButton.setEnabled(True)
        sizePolicy1.setHeightForWidth(self.repButton.sizePolicy().hasHeightForWidth())
        self.repButton.setSizePolicy(sizePolicy1)
        self.repButton.setMaximumSize(QSize(141, 43))
        self.repButton.setFont(font3)
        self.repButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.repButton.setStyleSheet(u"QPushButton {\n"
"    background-color: #FF4136;\n"
"	color: rgb(245,245,245);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"   background-color: #FF6F5E;\n"
"	color: white;\n"
"    border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"   background-color: rgb(177, 185, 187);\n"
"	color: white;\n"
"}")

        self.horizontalLayout_2.addWidget(self.repButton)

        self.horizontalSpacer_5 = QSpacerItem(50, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_2.addItem(self.horizontalSpacer_5)


        self.verticalLayout.addWidget(self.horizontalWidget_8)


        self.verticalLayout_4.addWidget(self.voterFrame)

        self.stackedWidget.addWidget(self.page1)
        self.page2 = QWidget()
        self.page2.setObjectName(u"page2")
        self.voterFrame2 = QFrame(self.page2)
        self.voterFrame2.setObjectName(u"voterFrame2")
        self.voterFrame2.setGeometry(QRect(240, 20, 831, 681))
        self.voterFrame2.setMaximumSize(QSize(861, 700))
        self.voterFrame2.setStyleSheet(u"#voterFrame2 {\n"
"   background-color: rgba(46, 47, 56, 0.8);\n"
"   border-radius: 15px;\n"
"   border-style: outset;\n"
"   border-width: 2px;\n"
"   border-radius: 15px;\n"
"   border-color: black;\n"
"   padding: 4px;\n"
"}\n"
"")
        self.voterFrame2.setFrameShape(QFrame.Shape.StyledPanel)
        self.voterFrame2.setFrameShadow(QFrame.Shadow.Raised)
        self.verticalFrame_2 = QFrame(self.voterFrame2)
        self.verticalFrame_2.setObjectName(u"verticalFrame_2")
        self.verticalFrame_2.setGeometry(QRect(80, 20, 666, 631))
        self.verticalFrame_2.setStyleSheet(u"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;")
        self.verticalLayout_5 = QVBoxLayout(self.verticalFrame_2)
        self.verticalLayout_5.setObjectName(u"verticalLayout_5")
        self.horizontalFrame_12 = QFrame(self.verticalFrame_2)
        self.horizontalFrame_12.setObjectName(u"horizontalFrame_12")
        self.horizontalFrame_12.setMinimumSize(QSize(0, 51))
        self.horizontalFrame_12.setMaximumSize(QSize(16777215, 51))
        self.horizontalFrame_12.setStyleSheet(u"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;")
        self.horizontalLayout_19 = QHBoxLayout(self.horizontalFrame_12)
        self.horizontalLayout_19.setObjectName(u"horizontalLayout_19")
        self.horizontalSpacer_3 = QSpacerItem(170, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_19.addItem(self.horizontalSpacer_3)

        self.VoterSubmissionLabel = QLabel(self.horizontalFrame_12)
        self.VoterSubmissionLabel.setObjectName(u"VoterSubmissionLabel")
        self.VoterSubmissionLabel.setMaximumSize(QSize(221, 51))
        font8 = QFont()
        font8.setFamilies([u"Arial"])
        font8.setPointSize(18)
        font8.setBold(True)
        font8.setItalic(False)
        self.VoterSubmissionLabel.setFont(font8)
        self.VoterSubmissionLabel.setStyleSheet(u"QLabel {\n"
"   color: rgb(245,245,245);\n"
"}")
        self.VoterSubmissionLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.horizontalLayout_19.addWidget(self.VoterSubmissionLabel)

        self.horizontalSpacer_7 = QSpacerItem(170, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_19.addItem(self.horizontalSpacer_7)


        self.verticalLayout_5.addWidget(self.horizontalFrame_12)

        self.verticalSpacer_3 = QSpacerItem(661, 18, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)

        self.verticalLayout_5.addItem(self.verticalSpacer_3)

        self.formFrame = QFrame(self.verticalFrame_2)
        self.formFrame.setObjectName(u"formFrame")
        self.formFrame.setStyleSheet(u"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;")
        self.formLayout = QFormLayout(self.formFrame)
        self.formLayout.setObjectName(u"formLayout")
        self.formLayout.setRowWrapPolicy(QFormLayout.RowWrapPolicy.DontWrapRows)
        self.formLayout.setLabelAlignment(Qt.AlignmentFlag.AlignCenter)
        self.formLayout.setFormAlignment(Qt.AlignmentFlag.AlignCenter)
        self.formLayout.setHorizontalSpacing(8)
        self.formLayout.setVerticalSpacing(8)
        self.formLayout.setContentsMargins(-1, 2, -1, 2)
        self.FirstNameLabel = QLabel(self.formFrame)
        self.FirstNameLabel.setObjectName(u"FirstNameLabel")
        self.FirstNameLabel.setMaximumSize(QSize(111, 41))
        self.FirstNameLabel.setFont(font1)
        self.FirstNameLabel.setStyleSheet(u"QLabel {\n"
"    background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.formLayout.setWidget(0, QFormLayout.ItemRole.LabelRole, self.FirstNameLabel)

        self.FirstNameLineEdit = QLineEdit(self.formFrame)
        self.FirstNameLineEdit.setObjectName(u"FirstNameLineEdit")
        sizePolicy1.setHeightForWidth(self.FirstNameLineEdit.sizePolicy().hasHeightForWidth())
        self.FirstNameLineEdit.setSizePolicy(sizePolicy1)
        self.FirstNameLineEdit.setMinimumSize(QSize(175, 41))
        self.FirstNameLineEdit.setMaximumSize(QSize(175, 41))
        self.FirstNameLineEdit.setFont(font7)
        self.FirstNameLineEdit.setStyleSheet(u"QLineEdit {\n"
"    background-color: rgba(32,33,35,255);\n"
"	color: rgb(245,245,245);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}")
        self.FirstNameLineEdit.setMaxLength(20)

        self.formLayout.setWidget(0, QFormLayout.ItemRole.FieldRole, self.FirstNameLineEdit)

        self.LastNameLabel = QLabel(self.formFrame)
        self.LastNameLabel.setObjectName(u"LastNameLabel")
        self.LastNameLabel.setMaximumSize(QSize(107, 41))
        self.LastNameLabel.setFont(font1)
        self.LastNameLabel.setStyleSheet(u"QLabel {\n"
"    background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.formLayout.setWidget(1, QFormLayout.ItemRole.LabelRole, self.LastNameLabel)

        self.LastNameLineEdit = QLineEdit(self.formFrame)
        self.LastNameLineEdit.setObjectName(u"LastNameLineEdit")
        sizePolicy1.setHeightForWidth(self.LastNameLineEdit.sizePolicy().hasHeightForWidth())
        self.LastNameLineEdit.setSizePolicy(sizePolicy1)
        self.LastNameLineEdit.setMinimumSize(QSize(175, 41))
        self.LastNameLineEdit.setMaximumSize(QSize(175, 41))
        self.LastNameLineEdit.setFont(font7)
        self.LastNameLineEdit.setStyleSheet(u"QLineEdit {\n"
"    background-color: rgba(32,33,35,255);\n"
"	color: rgb(245,245,245);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}")
        self.LastNameLineEdit.setMaxLength(20)

        self.formLayout.setWidget(1, QFormLayout.ItemRole.FieldRole, self.LastNameLineEdit)

        self.AddressLabel = QLabel(self.formFrame)
        self.AddressLabel.setObjectName(u"AddressLabel")
        self.AddressLabel.setMaximumSize(QSize(86, 31))
        self.AddressLabel.setFont(font1)
        self.AddressLabel.setStyleSheet(u"QLabel {\n"
"    background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.formLayout.setWidget(2, QFormLayout.ItemRole.LabelRole, self.AddressLabel)

        self.AddressLineEdit = QLineEdit(self.formFrame)
        self.AddressLineEdit.setObjectName(u"AddressLineEdit")
        sizePolicy1.setHeightForWidth(self.AddressLineEdit.sizePolicy().hasHeightForWidth())
        self.AddressLineEdit.setSizePolicy(sizePolicy1)
        self.AddressLineEdit.setMinimumSize(QSize(175, 41))
        self.AddressLineEdit.setMaximumSize(QSize(175, 41))
        self.AddressLineEdit.setFont(font7)
        self.AddressLineEdit.setStyleSheet(u"QLineEdit {\n"
"    background-color: rgba(32,33,35,255);\n"
"	color: rgb(245,245,245);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}")
        self.AddressLineEdit.setMaxLength(20)

        self.formLayout.setWidget(2, QFormLayout.ItemRole.FieldRole, self.AddressLineEdit)

        self.CityLabel = QLabel(self.formFrame)
        self.CityLabel.setObjectName(u"CityLabel")
        self.CityLabel.setMaximumSize(QSize(43, 31))
        self.CityLabel.setFont(font1)
        self.CityLabel.setStyleSheet(u"QLabel {\n"
"    background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.formLayout.setWidget(3, QFormLayout.ItemRole.LabelRole, self.CityLabel)

        self.CityLineEdit = QLineEdit(self.formFrame)
        self.CityLineEdit.setObjectName(u"CityLineEdit")
        sizePolicy1.setHeightForWidth(self.CityLineEdit.sizePolicy().hasHeightForWidth())
        self.CityLineEdit.setSizePolicy(sizePolicy1)
        self.CityLineEdit.setMinimumSize(QSize(175, 41))
        self.CityLineEdit.setMaximumSize(QSize(175, 41))
        self.CityLineEdit.setFont(font7)
        self.CityLineEdit.setStyleSheet(u"QLineEdit {\n"
"    background-color: rgba(32,33,35,255);\n"
"	color: rgb(245,245,245);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}")
        self.CityLineEdit.setMaxLength(20)

        self.formLayout.setWidget(3, QFormLayout.ItemRole.FieldRole, self.CityLineEdit)

        self.StateLabel = QLabel(self.formFrame)
        self.StateLabel.setObjectName(u"StateLabel")
        self.StateLabel.setMaximumSize(QSize(55, 31))
        self.StateLabel.setFont(font1)
        self.StateLabel.setStyleSheet(u"QLabel {\n"
"    background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.formLayout.setWidget(4, QFormLayout.ItemRole.LabelRole, self.StateLabel)

        self.StateLineEdit = QLineEdit(self.formFrame)
        self.StateLineEdit.setObjectName(u"StateLineEdit")
        sizePolicy1.setHeightForWidth(self.StateLineEdit.sizePolicy().hasHeightForWidth())
        self.StateLineEdit.setSizePolicy(sizePolicy1)
        self.StateLineEdit.setMinimumSize(QSize(175, 41))
        self.StateLineEdit.setMaximumSize(QSize(175, 41))
        self.StateLineEdit.setFont(font7)
        self.StateLineEdit.setStyleSheet(u"QLineEdit {\n"
"    background-color: rgba(32,33,35,255);\n"
"	color: rgb(245,245,245);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}")
        self.StateLineEdit.setMaxLength(20)

        self.formLayout.setWidget(4, QFormLayout.ItemRole.FieldRole, self.StateLineEdit)

        self.IdLabel = QLabel(self.formFrame)
        self.IdLabel.setObjectName(u"IdLabel")
        self.IdLabel.setMaximumSize(QSize(26, 31))
        self.IdLabel.setFont(font1)
        self.IdLabel.setStyleSheet(u"QLabel {\n"
"    background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;\n"
"}")

        self.formLayout.setWidget(5, QFormLayout.ItemRole.LabelRole, self.IdLabel)

        self.IdLineEdit = QLineEdit(self.formFrame)
        self.IdLineEdit.setObjectName(u"IdLineEdit")
        sizePolicy1.setHeightForWidth(self.IdLineEdit.sizePolicy().hasHeightForWidth())
        self.IdLineEdit.setSizePolicy(sizePolicy1)
        self.IdLineEdit.setMinimumSize(QSize(175, 41))
        self.IdLineEdit.setMaximumSize(QSize(175, 41))
        self.IdLineEdit.setFont(font7)
        self.IdLineEdit.setStyleSheet(u"QLineEdit {\n"
"    background-color: rgba(32,33,35,255);\n"
"	color: rgb(245,245,245);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}")
        self.IdLineEdit.setMaxLength(9)

        self.formLayout.setWidget(5, QFormLayout.ItemRole.FieldRole, self.IdLineEdit)

        self.PasswordLabel = QLabel(self.formFrame)
        self.PasswordLabel.setObjectName(u"PasswordLabel")
        self.PasswordLabel.setMinimumSize(QSize(101, 31))
        self.PasswordLabel.setMaximumSize(QSize(101, 31))
        self.PasswordLabel.setFont(font1)
        self.PasswordLabel.setStyleSheet(u"QLabel {\n"
"   color: rgb(245,245,245);\n"
"}")

        self.formLayout.setWidget(6, QFormLayout.ItemRole.LabelRole, self.PasswordLabel)

        self.PasswordLineEdit = QLineEdit(self.formFrame)
        self.PasswordLineEdit.setObjectName(u"PasswordLineEdit")
        sizePolicy1.setHeightForWidth(self.PasswordLineEdit.sizePolicy().hasHeightForWidth())
        self.PasswordLineEdit.setSizePolicy(sizePolicy1)
        self.PasswordLineEdit.setMinimumSize(QSize(175, 41))
        self.PasswordLineEdit.setMaximumSize(QSize(175, 41))
        self.PasswordLineEdit.setFont(font7)
        self.PasswordLineEdit.setStyleSheet(u"QLineEdit {\n"
"    background-color: rgba(32,33,35,255);\n"
"	color: rgb(245,245,245);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}")
        self.PasswordLineEdit.setMaxLength(16)
        self.PasswordLineEdit.setCursorPosition(14)

        self.formLayout.setWidget(6, QFormLayout.ItemRole.FieldRole, self.PasswordLineEdit)


        self.verticalLayout_5.addWidget(self.formFrame)

        self.verticalSpacer_4 = QSpacerItem(661, 20, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)

        self.verticalLayout_5.addItem(self.verticalSpacer_4)

        self.horizontalWidget_10 = QWidget(self.verticalFrame_2)
        self.horizontalWidget_10.setObjectName(u"horizontalWidget_10")
        self.horizontalWidget_10.setMinimumSize(QSize(0, 71))
        self.horizontalWidget_10.setMaximumSize(QSize(661, 71))
        self.horizontalWidget_10.setStyleSheet(u"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;")
        self.horizontalLayout_10 = QHBoxLayout(self.horizontalWidget_10)
        self.horizontalLayout_10.setObjectName(u"horizontalLayout_10")
        self.horizontalSpacer_26 = QSpacerItem(100, 20, QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_10.addItem(self.horizontalSpacer_26)

        self.SubmitInfoLabel = QLabel(self.horizontalWidget_10)
        self.SubmitInfoLabel.setObjectName(u"SubmitInfoLabel")
        self.SubmitInfoLabel.setMaximumSize(QSize(511, 51))
        self.SubmitInfoLabel.setFont(font6)
        self.SubmitInfoLabel.setStyleSheet(u"QLabel {\n"
"   color: rgb(245,245,245);\n"
"}")
        self.SubmitInfoLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.horizontalLayout_10.addWidget(self.SubmitInfoLabel)

        self.horizontalSpacer_27 = QSpacerItem(100, 20, QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_10.addItem(self.horizontalSpacer_27)


        self.verticalLayout_5.addWidget(self.horizontalWidget_10)

        self.verticalSpacer_5 = QSpacerItem(661, 20, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)

        self.verticalLayout_5.addItem(self.verticalSpacer_5)

        self.horizontalFrame_20 = QFrame(self.verticalFrame_2)
        self.horizontalFrame_20.setObjectName(u"horizontalFrame_20")
        self.horizontalFrame_20.setMinimumSize(QSize(0, 53))
        self.horizontalFrame_20.setMaximumSize(QSize(16777215, 53))
        self.horizontalFrame_20.setStyleSheet(u"   background-color: none;\n"
"   color: rgb(245,245,245);\n"
"   border: none;")
        self.horizontalLayout_27 = QHBoxLayout(self.horizontalFrame_20)
        self.horizontalLayout_27.setObjectName(u"horizontalLayout_27")
        self.horizontalSpacer_61 = QSpacerItem(150, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_27.addItem(self.horizontalSpacer_61)

        self.CancelButton = QPushButton(self.horizontalFrame_20)
        self.CancelButton.setObjectName(u"CancelButton")
        sizePolicy1.setHeightForWidth(self.CancelButton.sizePolicy().hasHeightForWidth())
        self.CancelButton.setSizePolicy(sizePolicy1)
        self.CancelButton.setMinimumSize(QSize(141, 43))
        self.CancelButton.setMaximumSize(QSize(141, 43))
        self.CancelButton.setFont(font3)
        self.CancelButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.CancelButton.setStyleSheet(u"QPushButton {\n"
"    background-color: rgba(32,33,35,255);\n"
"	color: rgb(245,245,245);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"   background-color: rgb(87, 89, 101);\n"
"	color: white;\n"
"    border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"   background-color: rgb(177, 185, 187);\n"
"	color: white;\n"
"}")

        self.horizontalLayout_27.addWidget(self.CancelButton)

        self.horizontalSpacer_62 = QSpacerItem(40, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_27.addItem(self.horizontalSpacer_62)

        self.SubmitButton = QPushButton(self.horizontalFrame_20)
        self.SubmitButton.setObjectName(u"SubmitButton")
        sizePolicy1.setHeightForWidth(self.SubmitButton.sizePolicy().hasHeightForWidth())
        self.SubmitButton.setSizePolicy(sizePolicy1)
        self.SubmitButton.setMinimumSize(QSize(141, 43))
        self.SubmitButton.setMaximumSize(QSize(141, 43))
        self.SubmitButton.setFont(font3)
        self.SubmitButton.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.SubmitButton.setStyleSheet(u"QPushButton {\n"
"    background-color: rgba(32,33,35,255);\n"
"	color: rgb(245,245,245);\n"
"	border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"   background-color: rgb(87, 89, 101);\n"
"	color: white;\n"
"    border-radius: 15px;\n"
"	border-style: outset;\n"
"	border-width: 2px;\n"
"	border-radius: 15px;\n"
"	border-color: black;\n"
"	padding: 4px;\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"   background-color: rgb(177, 185, 187);\n"
"	color: white;\n"
"}")

        self.horizontalLayout_27.addWidget(self.SubmitButton)

        self.horizontalSpacer_63 = QSpacerItem(150, 20, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_27.addItem(self.horizontalSpacer_63)


        self.verticalLayout_5.addWidget(self.horizontalFrame_20)

        self.stackedWidget.addWidget(self.page2)
        SecureVote.setCentralWidget(self.centralwidget)

        self.retranslateUi(SecureVote)

        self.stackedWidget.setCurrentIndex(0)


        QMetaObject.connectSlotsByName(SecureVote)
    # setupUi

    def retranslateUi(self, SecureVote):
        SecureVote.setWindowTitle(QCoreApplication.translate("SecureVote", u"SecureVote", None))
        self.voteCounterLabel.setText(QCoreApplication.translate("SecureVote", u"Remaining Votes:", None))
        self.voteCounter.setText(QCoreApplication.translate("SecureVote", u"13", None))
        self.topLabel.setText(QCoreApplication.translate("SecureVote", u"Secure Voting System", None))
        self.addVoterButton.setText(QCoreApplication.translate("SecureVote", u"Add Voter", None))
        self.currentResultLabel.setText(QCoreApplication.translate("SecureVote", u"Current Results", None))
        self.demLabel.setText(QCoreApplication.translate("SecureVote", u"Democrat Party:", None))
        self.demVote.setText(QCoreApplication.translate("SecureVote", u"20%", None))
        self.repLabel.setText(QCoreApplication.translate("SecureVote", u"Republican Party:", None))
        self.repVote.setText(QCoreApplication.translate("SecureVote", u"80%", None))
        self.voterLabel.setText(QCoreApplication.translate("SecureVote", u"Voter Information", None))
        self.nameLabel.setText(QCoreApplication.translate("SecureVote", u"Name:", None))
        self.name.setText(QCoreApplication.translate("SecureVote", u"Michle Jackson", None))
        self.addressLabel.setText(QCoreApplication.translate("SecureVote", u"Address:", None))
        self.address.setText(QCoreApplication.translate("SecureVote", u"456 Maple Avenue", None))
        self.cityLabel.setText(QCoreApplication.translate("SecureVote", u"City:", None))
        self.city.setText(QCoreApplication.translate("SecureVote", u"Los Angeles", None))
        self.stateLabel.setText(QCoreApplication.translate("SecureVote", u"State:", None))
        self.state.setText(QCoreApplication.translate("SecureVote", u"North Carolina", None))
        self.infoLabel.setText(QCoreApplication.translate("SecureVote", u"Verifying Voter, Please Wait...", None))
        self.verificationLabel.setText(QCoreApplication.translate("SecureVote", u"Voter Verification ", None))
        self.idLabel.setText(QCoreApplication.translate("SecureVote", u"Voter ID:", None))
        self.idLineEdit.setInputMask("")
        self.idLineEdit.setText("")
        self.passwordLabel.setText(QCoreApplication.translate("SecureVote", u"Password:", None))
        self.passwordLineEdit.setText("")
        self.verifyButton.setText(QCoreApplication.translate("SecureVote", u"Verify Voter", None))
        self.chooseLabel.setText(QCoreApplication.translate("SecureVote", u"Choose One Candidate:", None))
        self.demButton.setText(QCoreApplication.translate("SecureVote", u"Democrat", None))
        self.repButton.setText(QCoreApplication.translate("SecureVote", u"Republican", None))
        self.VoterSubmissionLabel.setText(QCoreApplication.translate("SecureVote", u"Voter Submission", None))
        self.FirstNameLabel.setText(QCoreApplication.translate("SecureVote", u"First Name:", None))
        self.FirstNameLineEdit.setText(QCoreApplication.translate("SecureVote", u"Marilyn", None))
        self.LastNameLabel.setText(QCoreApplication.translate("SecureVote", u"Last Name:", None))
        self.LastNameLineEdit.setText(QCoreApplication.translate("SecureVote", u" Monroe", None))
        self.AddressLabel.setText(QCoreApplication.translate("SecureVote", u"Address:", None))
        self.AddressLineEdit.setText(QCoreApplication.translate("SecureVote", u"Merilin Street 6742", None))
        self.CityLabel.setText(QCoreApplication.translate("SecureVote", u"City:", None))
        self.CityLineEdit.setText(QCoreApplication.translate("SecureVote", u"Los Angeles", None))
        self.StateLabel.setText(QCoreApplication.translate("SecureVote", u"State:", None))
        self.StateLineEdit.setText(QCoreApplication.translate("SecureVote", u"California", None))
        self.IdLabel.setText(QCoreApplication.translate("SecureVote", u"ID:", None))
        self.IdLineEdit.setText(QCoreApplication.translate("SecureVote", u"123456789", None))
        self.PasswordLabel.setText(QCoreApplication.translate("SecureVote", u"Password:", None))
        self.PasswordLineEdit.setText(QCoreApplication.translate("SecureVote", u"12345678912345", None))
        self.SubmitInfoLabel.setText(QCoreApplication.translate("SecureVote", u"ID must be 9 digits and password at least 6 characters.\n"
" Fields must be more then 1 character.", None))
        self.CancelButton.setText(QCoreApplication.translate("SecureVote", u"Cancel", None))
        self.SubmitButton.setText(QCoreApplication.translate("SecureVote", u"Submit", None))
    # retranslateUi

