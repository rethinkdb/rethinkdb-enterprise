// Copyright 2010-2016 RethinkDB, all rights reserved.
#ifndef CLUSTERING_ADMINISTRATION_LOGS_AUDIT_MANIFEST_HPP_
#define CLUSTERING_ADMINISTRATION_LOGS_AUDIT_MANIFEST_HPP_

#include <string>

std::string get_audit_manifest(const std::string &path) {
    std::string manifest = "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?> \
<instrumentationManifest xsi:schemaLocation=\"http://schemas.microsoft.com/win/2004/08/events eventman.xsd\" xmlns=\"http://schemas.microsoft.com/win/2004/08/events\" xmlns:win=\"http://manifests.microsoft.com/win/2004/08/windows/events\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:trace=\"http://schemas.microsoft.com/win/2004/08/events/trace\">\
	<instrumentation>\
		<events>\
			<provider name=\"RethinkDB\" guid=\"{A478AC50-01C7-42FF-B093-035816B1072F}\" symbol=\"RethinkDB\" resourceFileName=\"" + path + "\" messageFileName=\"" + path + "\">\
				<events>\
					<event symbol=\"AuditLogNotice\" value=\"1\" version=\"0\" channel=\"Log\" level=\"Notice\" template=\"AuditLogMessage\" keywords=\"Audit \" message=\"$(string.RethinkDB.event.1.message)\">\
					</event>\
					<event symbol=\"AuditLogError\" value=\"2\" version=\"0\" channel=\"Log\" level=\"Error\" template=\"AuditLogMessage\" keywords=\"Audit \" message=\"$(string.RethinkDB.event.2.message)\">\
					</event>\
					<event symbol=\"AuditLogInfo\" value=\"3\" version=\"0\" channel=\"Log\" level=\"Info\" template=\"AuditLogMessage\" keywords=\"Audit \" message=\"$(string.RethinkDB.event.3.message)\">\
					</event>\
					<event symbol=\"AuditLogWarn\" value=\"4\" version=\"0\" channel=\"Log\" level=\"Warn\" template=\"AuditLogMessage\" keywords=\"Audit \" message=\"$(string.RethinkDB.event.4.message)\">\
					</event>\
					<event symbol=\"AuditLogCritical\" value=\"5\" version=\"0\" channel=\"Log\" level=\"Critical\" template=\"AuditLogMessage\" keywords=\"Audit \" message=\"$(string.RethinkDB.event.5.message)\">\
					</event>\
					<event symbol=\"AuditLogAlert\" value=\"6\" version=\"0\" channel=\"Log\" level=\"Alert\" template=\"AuditLogMessage\" keywords=\"Audit \" message=\"$(string.RethinkDB.event.6.message)\">\
					</event>\
					<event symbol=\"AuditLogEmergency\" value=\"7\" version=\"0\" channel=\"Log\" level=\"Emergency\" template=\"AuditLogMessage\" keywords=\"Audit \" message=\"$(string.RethinkDB.event.7.message)\">\
					</event>\
				</events>\
				<levels>\
					<level name=\"Debug\" symbol=\"Debug\" value=\"16\" message=\"$(string.RethinkDB.level.Debug.message)\">\
					</level>\
					<level name=\"Info\" symbol=\"Info\" value=\"17\" message=\"$(string.RethinkDB.level.Info.message)\">\
					</level>\
					<level name=\"Notice\" symbol=\"Notice\" value=\"18\" message=\"$(string.RethinkDB.level.Notice.message)\">\
					</level>\
					<level name=\"Warn\" symbol=\"Warn\" value=\"19\" message=\"$(string.RethinkDB.level.Warn.message)\">\
					</level>\
					<level name=\"Error\" symbol=\"Error\" value=\"20\" message=\"$(string.RethinkDB.level.Error.message)\">\
					</level>\
					<level name=\"Critical\" symbol=\"Critical\" value=\"21\" message=\"$(string.RethinkDB.level.Critical.message)\">\
					</level>\
					<level name=\"Alert\" symbol=\"Alert\" value=\"22\" message=\"$(string.RethinkDB.level.Alert.message)\">\
					</level>\
					<level name=\"Emergency\" symbol=\"Emergency\" value=\"23\" message=\"$(string.RethinkDB.level.Emergency.message)\">\
					</level>\
				</levels>\
				<channels>\
					<channel name=\"Log\" chid=\"Log\" symbol=\"AuditLog\" type=\"Operational\" enabled=\"false\">\
					</channel>\
				</channels>\
				<keywords>\
					<keyword name=\"Audit\" symbol=\"Audit\" mask=\"0x800000000000\" message=\"$(string.RethinkDB.keyword.Audit.message)\">\
					</keyword>\
				</keywords>\
				<templates>\
					<template tid=\"AuditLogMessage\">\
						<data name=\"Message\" inType=\"win:UnicodeString\" outType=\"xs:string\">\
						</data>\
					</template>\
				</templates>\
			</provider>\
		</events>\
	</instrumentation>\
	<localization>\
		<resources culture=\"en-US\">\
			<stringTable>\
				<string id=\"RethinkDB.level.Warn.message\" value=\"Warn\">\
				</string>\
				<string id=\"RethinkDB.level.Notice.message\" value=\"Notice\">\
				</string>\
				<string id=\"RethinkDB.level.Info.message\" value=\"Info\">\
				</string>\
				<string id=\"RethinkDB.level.Error.message\" value=\"Error\">\
				</string>\
				<string id=\"RethinkDB.level.Emergency.message\" value=\"Emergency\">\
				</string>\
				<string id=\"RethinkDB.level.Debug.message\" value=\"Debug\">\
				</string>\
				<string id=\"RethinkDB.level.Critical.message\" value=\"Critical\">\
				</string>\
				<string id=\"RethinkDB.level.Alert.message\" value=\"Alert\">\
				</string>\
				<string id=\"RethinkDB.keyword.Audit.message\" value=\"Audit\">\
				</string>\
				<string id=\"RethinkDB.event.7.message\" value=\"Emergency: %1\">\
				</string>\
				<string id=\"RethinkDB.event.6.message\" value=\"Alert: %1\">\
				</string>\
				<string id=\"RethinkDB.event.5.message\" value=\"Critical: %1\">\
				</string>\
				<string id=\"RethinkDB.event.4.message\" value=\"Warn: %1\">\
				</string>\
				<string id=\"RethinkDB.event.3.message\" value=\"Info: %1\">\
				</string>\
				<string id=\"RethinkDB.event.2.message\" value=\"Error: %1\">\
				</string>\
				<string id=\"RethinkDB.event.1.message\" value=\"Notice: %1\">\
				</string>\
			</stringTable>\
		</resources>\
	</localization>\
</instrumentationManifest>";

    return manifest;
}

#endif //CLUSTERING_ADMINISTRATION_LOGS_AUDIT_MANIFEST_HPP_
