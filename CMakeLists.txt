# QCVECheckReport project

# file: CMakeLists.txt

# author: Raffaele de Cicco <decicco.raffaele@gmail.com>

# abstract:
# This tool is able to create a report to analyze CVE of a yocto build image using CVECheck json report and
# NVD CVE DB of NIST created by the same tool retriving information by https://www.nist.gov/

# copyright: Copyright 2024 Raffaele de Cicco <decicco.raffaele@gmail.com>

# legalese:
# Licensed under the General Public License, Version 3.0 (the "License");
# you may not use this file except in compliance with the License.
# See file gnu-gpl-v3.0.md or obtain a copy of the License at

#   https://www.gnu.org/licenses/gpl-3.0.html

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.29.3)

project(QCVECheckReport VERSION 0.3 LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(USE_PDFWRITER False)

find_package(QT NAMES Qt6 Qt5 COMPONENTS Widgets LinguistTools REQUIRED)
find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Widgets LinguistTools REQUIRED)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Sql)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Charts)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Concurrent)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Gui WebEngineWidgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Pdf)

set(TS_FILES QCVECheckReport_en_US.ts)

set(PROJECT_FORMS
    qcvecheckapp.ui
    dialogimportcvereport.ui
    mdisubwindow.ui
    dialogimportcvedb.ui
    mdicvedata.ui
    mdipdfreport.ui
)

set(PROJECT_HEADERS
    DTO/abstractdto.h
    DTO/cvereportdto.h
    DTO/packagedto.h
    DTO/packageproductdto.h
    DTO/issuedto.h
    DTO/nvddto.h
    DTO/productdto.h
    DAO/abstractdao.h
    DAO/cvereportdao.h
    DAO/packagedao.h
    DAO/packageproductdao.h
    DAO/issuedao.h
    DAO/nvddao.h
    DAO/productdao.h
    qcvecheckapp.h
    qsqlitemanager.h
    jsoncvecheckreportmanager.h
    dialogimportcvereport.h
    mdisubwindow.h
    reportdata.h
    dialogimportcvedb.h
    mdicvedata.h
    mdipdfreport.h
    html2pdfconverter.h
)

set(PROJECT_SOURCES
    DAO/cvereportdao.cpp
    DAO/packagedao.cpp
    DAO/packageproductdao.cpp
    DAO/issuedao.cpp
    DAO/nvddao.cpp
    DAO/productdao.cpp
    main.cpp
    qcvecheckapp.cpp
    qsqlitemanager.cpp
    jsoncvecheckreportmanager.cpp
    dialogimportcvereport.cpp
    mdisubwindow.cpp
    reportdata.cpp
    qsqltableview.cpp
    dialogimportcvedb.cpp
    mdicvedata.cpp
    mdipdfreport.cpp
    html2pdfconverter.cpp
    ${TS_FILES}
)

set(PROJECT_DOCUMENTATION
    Documentation/CVEReportCVEs.png
    Documentation/CVEReportGeneralInformation.png
    Documentation/CVEReportIgnoredCVEs.png
    Documentation/CVEReportNavigator.png
    Documentation/CVEReportPackages.png
    Documentation/CVEReportSummary.png
    Documentation/cvss-v2-guide.pdf
    Documentation/cvss-v30-specification_v1.9.pdf
    Documentation/cvss-v31-specification_r1.pdf
    Documentation/cvss-v40-specification.pdf
    Documentation/CVSSDescription.md
    Documentation/DatabaseStructure.md
    Documentation/FileMenu.png
    Documentation/gnu-gpl-v3.0.md
    Documentation/HTMLReport.png
    Documentation/ImportCVEDb.png
    Documentation/ImportedJson.png
    Documentation/Index.md
    Documentation/MainWindow.png
    Documentation/NVD-CVE-2024-45490.png
    Documentation/OpenDialog.png
    Documentation/QCVECheckReport.md
    Documentation/QtKitConfiguration.png
    Documentation/Report.pdf
    Documentation/SavePDFReport.png
    Documentation/SearchCVEs.png
    Documentation/SoftwareArchitecture.md
    Documentation/SoftwareDescription.md
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)

qt_add_executable(QCVECheckReport
        MANUAL_FINALIZATION
        ${PROJECT_FORMS}
        ${PROJECT_HEADERS}
        ${PROJECT_SOURCES}
        ${PROJECT_DOCUMENTATION}
        QCVECheckReportResources.qrc
        LICENSE
        README.md
    )

# Define target properties for Android with Qt 6 as:
#    set_property(TARGET QCVECheckReport APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation

    qt_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})
else()
    if(ANDROID)
        add_library(QCVECheckReport SHARED
            ${PROJECT_SOURCES}
        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
        add_executable(QCVECheckReport
            ${PROJECT_SOURCES}
        )
    endif()

    qt5_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})
endif()

target_link_libraries(QCVECheckReport PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)
target_link_libraries(QCVECheckReport PRIVATE Qt${QT_VERSION_MAJOR}::Sql)
target_link_libraries(QCVECheckReport PRIVATE Qt${QT_VERSION_MAJOR}::Charts)
target_link_libraries(QCVECheckReport PRIVATE Qt${QT_VERSION_MAJOR}::Concurrent)
target_link_libraries(QCVECheckReport PRIVATE
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Gui
    Qt${QT_VERSION_MAJOR}::WebEngineWidgets
)
target_link_libraries(QCVECheckReport PRIVATE Qt${QT_VERSION_MAJOR}::Pdf)

if(USE_PDFWRITER)
    add_compile_definitions(PDFWRITER 1)

    include(FetchContent)

    FetchContent_Declare(
      PDFHummus
      GIT_REPOSITORY https://github.com/galkahana/PDF-Writer.git
      GIT_TAG        v4.6.2
      FIND_PACKAGE_ARGS
    )
    FetchContent_MakeAvailable(PDFHummus)

    target_link_libraries(QCVECheckReport PRIVATE PDFHummus::PDFWriter)
endif()

set_target_properties(QCVECheckReport PROPERTIES
    MACOSX_BUNDLE_GUI_IDENTIFIER my.example.com
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(QCVECheckReport)
endif()

configure_file(CVEReportsDB.db CVEReportsDB.db COPYONLY)
configure_file(DejaVuSerif.ttf DejaVuSerif.ttf COPYONLY)
configure_file(DejaVuSerif-Bold.ttf DejaVuSerif-Bold.ttf COPYONLY)
configure_file(CVE.png CVE.png COPYONLY)
configure_file(LICENSE LICENSE COPYONLY)
