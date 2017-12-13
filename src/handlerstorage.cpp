#include "handlerstorage.h"
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <boost/assign.hpp>

HandlerStorage::HandlerStorage(const QString &storagePath, QObject *parent)
  : QObject(parent)
  , m_SettingsPath(storagePath + "/nxmhandler .ini")
{
  loadStore();
}

HandlerStorage::~HandlerStorage()
{
  saveStore();
}

void HandlerStorage::clear()
{
  m_Handlers.clear();
}

void HandlerStorage::registerProxy(const QString &proxyPath)
{
  //m_SettingsPath = QFileInfo(proxyPath).absolutePath() + "/nxmhandler.ini";
  QSettings settings("HKEY_CURRENT_USER\\Software\\Classes\\nxm\\", QSettings::NativeFormat);
  QString myExe = QString("\"%1\" ").arg(QDir::toNativeSeparators(proxyPath)).append("\"%1\"");
  settings.setValue("Default", "URL:NXM Protocol");
  settings.setValue("URL Protocol", "");
  settings.setValue("shell/open/command/Default", myExe);
  settings.sync();
}

void HandlerStorage::registerHandler(const QString &executable, bool prepend)
{
  QStringList games;
  for (const auto &game : this->knownGames()) {
    games.append(game.second);
  }
  registerHandler(games, executable, prepend, false);
}

void HandlerStorage::registerHandler(const QStringList &games, const QString &executable, bool prepend, bool rereg)
{
  QStringList gamesLower;
  for (const QString &game : games) {
    gamesLower.append(game.toLower());
  }
  for (auto iter = m_Handlers.begin(); iter != m_Handlers.end(); ++iter) {
    if (iter->executable.compare(executable, Qt::CaseInsensitive) == 0) {
      // executable already registered, update supported games and move it to top if requested
      if (rereg) {
        HandlerInfo info = *iter;
        info.games = gamesLower;
        m_Handlers.erase(iter);
        if (prepend) {
          m_Handlers.push_front(info);
        } else {
          m_Handlers.push_back(info);
        }
      } else {
        iter->games.append(gamesLower);
        iter->games.removeDuplicates();
      }
      return; // important: in the rereg-case we changed the list thus screwing up the iterator
    }
  }

  // executable not yet registered
  HandlerInfo info;
  info.ID = static_cast<int>(m_Handlers.size());
  info.games = gamesLower;
  info.executable = executable;
  if (prepend) {
    m_Handlers.push_front(info);
  } else {
    m_Handlers.push_back(info);
  }
}

QString HandlerStorage::getHandler(const QString &game) const
{
  for (const HandlerInfo &info : m_Handlers) {
    if (info.games.contains(game, Qt::CaseInsensitive)) {
      return info.executable;
    }
  }
  return QString();
}

std::vector<std::pair<QString, QString>> HandlerStorage::knownGames() const
{
  return {
    std::make_pair<QString, QString>("Oblivion", "oblivion"),
    std::make_pair<QString, QString>("Fallout 3", "fallout3"),
    std::make_pair<QString, QString>("Fallout 4", "fallout4"),
    std::make_pair<QString, QString>("Fallout NV", "falloutnv"),
    std::make_pair<QString, QString>("Skyrim", "skyrim"),
    std::make_pair<QString, QString>("SkyrimSE", "skyrimse"),
    std::make_pair<QString, QString>("Other", "other")
  };
}

QString HandlerStorage::stripCall(const QString &call)
{
  // TODO: this function is extremely naive and broken
  QString result = call;
  int idx = result.lastIndexOf(QRegExp("[A-Za-z]"));
  if (idx >= 0) {
    result.remove(idx + 1, result.size());
  }
  while (result.startsWith('"')) {
    result.remove(0, 1);
  }
  return result;
}

void HandlerStorage::loadStore()
{
  // register configured handlers
  QSettings settings(m_SettingsPath, QSettings::IniFormat);
  int size = settings.beginReadArray("handlers");
  for (int i = 0; i < size; ++i) {
    settings.setArrayIndex(i);
    HandlerInfo info;
    info.ID = i;
    info.games = settings.value("games").toString().split(",");
    info.executable = settings.value("executable").toString();
    if (QFile::exists(info.executable)) {
      m_Handlers.push_back(info);
    }
  }
  settings.endArray();


  // also register the global handler
  HandlerInfo info;
  QSettings handlerReg("HKEY_CLASSES_ROOT\\nxm\\", QSettings::NativeFormat);

  info.ID = static_cast<int>(m_Handlers.size());
  auto games = knownGames();
  QStringList ids;
  for (auto iter = games.begin(); iter != games.end(); ++iter) {
    ids.append(iter->second);
  }
  info.games = QStringList() << ids;
  info.executable = stripCall(handlerReg.value("shell/open/command/Default").toString());
  if (!info.executable.endsWith("nxmhandler.exe", Qt::CaseInsensitive)) {
    bool known = false;
    for (auto iter = m_Handlers.begin(); iter != m_Handlers.end(); ++iter) {
      if (iter->executable == info.executable) {
        known = true;
      }
    }
    if (!known) {
      m_Handlers.push_back(info);
    }
  }
}

void HandlerStorage::saveStore()
{
  QSettings settings(m_SettingsPath, QSettings::IniFormat);
  settings.beginWriteArray("handlers", static_cast<int>(m_Handlers.size()));
  int i = 0;
  for (auto iter = m_Handlers.begin(); iter != m_Handlers.end(); ++iter) {
    settings.setArrayIndex(i++);
    settings.setValue("games", iter->games.join(","));
    settings.setValue("executable", iter->executable);
  }
  settings.endArray();
}
