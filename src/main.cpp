#include "handlerstorage.h"
#include <utility.h>
#include <QApplication>
#include <QMessageBox>
#include <QAbstractButton>
#include <QDesktopServices>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QDateTime>
#include <QStandardPaths>
#include <QUrl>
#include <QUrlQuery>
#include "logger.h"


#pragma comment(linker, "/manifestDependency:\"name='dlls' processorArchitecture='x86' version='1.0.0.0' type='win32' \"")

using MOBase::ToWString;

static QString g_LogFileName = "";

void logHandler(QtMsgType type, const QMessageLogContext &context, const QString &message)
{
  if (g_LogFileName.isEmpty()) {
    return;
  }

  QFile file(g_LogFileName);

  // Prevent the log from growing infinitely
  if (file.size() > 10 * 1024 * 1024) {
    if (!file.open(QIODevice::WriteOnly)) {
      return;
    }
  } else if (!file.open(QIODevice::Append)) {
    return;
  }

  file.write(qUtf8Printable(QString("[%1] %2\n").arg(QDateTime::currentDateTime().toString()).arg(message)));
}

void handleLink(const QString &executable, const QString &arguments, const QString &link)
{
  QString quotedExecutable(executable);
  if (!quotedExecutable.contains(QRegularExpression("^\".*\"$"))) {
    quotedExecutable = '"' + quotedExecutable + '"';
  }

  QString quotedLink(link);
  if (!quotedLink.contains(QRegularExpression("^\".*\"$"))) {
    quotedLink = '"' + quotedLink + '"';
  }

  ::ShellExecute(nullptr, TEXT("open"), ToWString(quotedExecutable).c_str(),
                 ToWString(arguments + " " + quotedLink).c_str(),
                 ToWString(QFileInfo(quotedExecutable).absolutePath()).c_str(),
                 SW_SHOWNORMAL);
}

// ensure a nxmhandler.exe is registered to handle nxm-links, then load the
// handler storage for that registered instance
// (even if it's different from the one actually being run)
HandlerStorage *loadStorage()
{
  HandlerStorage *storage = nullptr;

  QDir globalStorage(
      QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation));
  globalStorage.cd("../ModOrganizer");
  QDir baseDir;
  if (globalStorage.exists()) {
    baseDir = globalStorage;
  } else {
    baseDir = QDir(qApp->applicationDirPath());
  }
  NxmHandler::LoggerInit(baseDir.filePath("nxmhandler.log"));
  QSettings handlerReg("HKEY_CURRENT_USER\\Software\\Classes\\nxm\\",
                       QSettings::NativeFormat);
  QStringList handlerVals = HandlerStorage::stripCall(handlerReg.value("shell/open/command/Default").toString());
  QString handlerPath = handlerVals.front();
  handlerVals.pop_front();
  QString handlerArgs = handlerVals.join(" ");

  QDir handlerBaseDir = QFileInfo(handlerPath).absoluteDir();

  if (globalStorage.exists("nxmhandler.ini") &&
      handlerPath.endsWith("nxmhandler.exe", Qt::CaseInsensitive) &&
      QFile::exists(handlerPath)) {
    // global configuration avaible - use it
    storage = new HandlerStorage(globalStorage.path());
  } else if (handlerBaseDir.exists("nxmhandler.ini") &&
             handlerPath.endsWith("nxmhandler.exe", Qt::CaseInsensitive) &&
             QFile::exists(handlerPath)) {
    // a portable installation is registered to handle links, use its
    // configuration
    storage = new HandlerStorage(QFileInfo(handlerPath).absolutePath());
  }
  return storage;
}

static void applyChromeFix()
{
  QString dataPath = QDir::fromNativeSeparators(QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation));
  QString fileName = QDir(dataPath + "/../google/chrome/user data/local state").canonicalPath();

  QFile chromeLocalState(fileName);

  if (!chromeLocalState.exists()) {
    // probably simply means that chrome isn't installed
    return;
  }

  if (!chromeLocalState.open(QIODevice::ReadOnly)) {
    // don't know, still no reason to report an error
    return;
  }

  QJsonParseError parseError;
  QJsonDocument document = QJsonDocument::fromJson(chromeLocalState.readAll(), &parseError);
  chromeLocalState.close();
  if (parseError.error == QJsonParseError::NoError) {
    QJsonObject docMap = document.object();
    QJsonObject handlers = docMap["protocol_handler"].toObject();
    // toObject returns empty object if the key doesn't exist. Therefore if excluded_schemes exists, protocol_handler existed as well
    if (handlers.contains("excluded_schemes")) {
      QJsonObject schemes = handlers["excluded_schemes"].toObject();
      if (schemes["modl"].toBool(true)) {
        if (QMessageBox::question(nullptr, "Apply Chrome fix",
                                  "Chrome may not support modl links even though the association is set up correctly. "
                                  "Do you want to apply a fix for that (You have to close chrome before pressing yes or "
                                  "this will have no effect!)?",
                                  QMessageBox::Yes | QMessageBox::No) == QMessageBox::No) {
          return;
        }
        schemes["modl"] = false;
        handlers["excluded_schemes"] = schemes;
        docMap["protocol_handler"] = handlers;
        QByteArray result = QJsonDocument(docMap).toJson();
        chromeLocalState.open(QIODevice::WriteOnly | QIODevice::Truncate);
        chromeLocalState.write(result);
        chromeLocalState.close();
        qDebug("chrome fix applied");
      }
    }
  }
}

void registerModlProxy()
{
    QSettings settings("HKEY_CURRENT_USER\\Software\\Classes\\modl\\", QSettings::NativeFormat);
    QString myExe = QString("\"%1\" ").arg(QDir::toNativeSeparators(QCoreApplication::applicationFilePath())).append("\"%1\"");
    settings.setValue("Default", "URL:MODL Protocol");
    settings.setValue("URL Protocol", "");
    settings.setValue("shell/open/command/Default", myExe);
    settings.sync();

    applyChromeFix();
}

int main(int argc, char *argv[])
{
  QApplication app(argc, argv);

  try {
    QStringList args = app.arguments();
    std::unique_ptr<HandlerStorage> storage(loadStorage());

    // Log the arguments
    qDebug(qUtf8Printable( "\"" + args.join("\" \"") + "\""));

    // No other logs, close the log
    NxmHandler::LoggerDeinit();

    // Acceptable arguments
    //
    // nxmhandler.exe
    //    forces registration and spawns handler window
    //
    // nxmhandler.exe reg|forcereg game1,game2,game3 C:/path/to/binary
    //    reg:      register if noregister==false
    //    forcereg: force registration
    //
    // nxmhandler.exe nxm://link/to/mod
    //    forwards link to registered handler

    if (args.count() > 1) {
      if ((args.at(1) == "reg") || (args.at(1) == "forcereg")) {
          registerModlProxy();
          return 0;
      } else if (args.at(1).startsWith("modl://")) {
          QUrl url(args.at(1));
          QUrlQuery query(url.query());

          if (storage.get() != nullptr) {
              QStringList handlerVals = storage->getHandler(url.host());
              QString executable = handlerVals.front();
              if (!executable.isEmpty()) {
                  handleLink(executable, "download", QUrl::fromPercentEncoding(query.queryItemValue("url").toUtf8()));
                  return 0;
              }
          }

          handleLink(QDir(qApp->applicationDirPath()).filePath("ModOrganizer.exe"), "download", QUrl::fromPercentEncoding(query.queryItemValue("url").toUtf8()));
          return 0;
      } else {
        QMessageBox::warning(nullptr, QObject::tr("Invalid Arguments"), QObject::tr("Invalid number of parameters"));
        return 1;
      }
      return 0;
    } else {
        if (QMessageBox::question(
            nullptr, QObject::tr("Create association"),
            QObject::tr("Associate %1 with modl:// links?").arg(QApplication::applicationName()),
            QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
            registerModlProxy();
        }
      return 0;
    }
  } catch (std::exception &e) {
    QMessageBox::critical(nullptr, QApplication::applicationName(),
                          QObject::tr("Uncaught exception:\n%1").arg(e.what()));
    throw;
  }
}
