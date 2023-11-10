cmake_minimum_required(VERSION 3.16)

add_executable(modlhandler)
mo2_configure_executable(modlhandler
	WARNINGS OFF
	PRIVATE_DEPENDS uibase)
mo2_install_target(modlhandler)

mo2_deploy_qt(BINARIES modlhandler.exe NOPLUGINS)
