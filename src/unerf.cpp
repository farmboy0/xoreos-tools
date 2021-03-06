/* xoreos-tools - Tools to help with xoreos development
 *
 * xoreos-tools is the legal property of its developers, whose names
 * can be found in the AUTHORS file distributed with this source
 * distribution.
 *
 * xoreos-tools is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * xoreos-tools is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with xoreos-tools. If not, see <http://www.gnu.org/licenses/>.
 */

/** @file
 *  Tool to extract ERF (.erf, .mod, .nwm, .sav) archives.
 */

#include <cstring>
#include <cstdio>

#include <vector>
#include <set>

#include "src/version/version.h"

#include "src/common/ustring.h"
#include "src/common/strutil.h"
#include "src/common/error.h"
#include "src/common/platform.h"
#include "src/common/readfile.h"
#include "src/common/md5.h"
#include "src/common/cli.h"

#include "src/aurora/util.h"
#include "src/aurora/erffile.h"

#include "src/archives/util.h"

#include "src/util.h"

enum Command {
	kCommandNone        = -1,
	kCommandInfo        =  0,
	kCommandList            ,
	kCommandListVerbose     ,
	kCommandExtract         ,
	kCommandExtractDir      ,
	kCommandMAX
};

const char *kCommandChar[kCommandMAX] = { "i", "l", "v", "e", "x" };

bool parseCommandLine(const std::vector<Common::UString> &argv, int &returnValue,
                      Command &command, Common::UString &archive, std::set<Common::UString> &files,
                      Aurora::GameID &game, std::vector<byte> &password);

bool parsePassword(const Common::UString &arg, std::vector<byte> &password);
bool readNWMMD5   (const Common::UString &arg, std::vector<byte> &password);

void displayInfo(Aurora::ERFFile &erf);

int main(int argc, char **argv) {
	initPlatform();

	try {
		std::vector<Common::UString> args;
		Common::Platform::getParameters(argc, argv, args);

		Aurora::GameID game = Aurora::kGameIDUnknown;

		int returnValue = 1;
		Command command = kCommandNone;
		Common::UString archive;
		std::set<Common::UString> files;
		std::vector<byte> password;

		if (!parseCommandLine(args, returnValue, command, archive, files, game, password))
			return returnValue;

		Aurora::ERFFile erf(new Common::ReadFile(archive), password);
		files = Archives::fixPathSeparator(files);

		if      (command == kCommandInfo)
			displayInfo(erf);
		else if (command == kCommandList)
			Archives::listFiles(erf, game, false);
		else if (command == kCommandListVerbose)
			Archives::listFiles(erf, game, true);
		else if (command == kCommandExtract)
			Archives::extractFiles(erf, game, false, files);
		else if (command == kCommandExtractDir)
			Archives::extractFiles(erf, game, true, files);

	} catch (...) {
		Common::exceptionDispatcherError();
	}

	return 0;
}

bool parsePassword(const Common::UString &arg, std::vector<byte> &password) {
	const size_t length = arg.size();

	password.clear();
	password.reserve(length / 2);

	size_t i = 0;
	byte c = 0x00;
	for (Common::UString::iterator s = arg.begin(); s != arg.end(); ++s, i++) {
		byte d = 0;

		if      (*s >= '0' && *s <= '9')
			d = *s - '0';
		else if (*s >= 'a' && *s <= 'f')
			d = *s - 'a' + 10;
		else if (*s >= 'A' && *s <= 'F')
			d = *s - 'A' + 10;
		else
			throw Common::Exception("0x%08X is not a valid hex digit", (uint) *s);

		if ((i % 2) == 1) {
			c |= d;

			password.push_back(c);

			c = 0x00;
		} else
			c |= d << 4;
	}
	return true;
}

bool readNWMMD5(const Common::UString &arg, std::vector<byte> &password) {
	Common::ReadFile keyFile(arg);

	Common::hashMD5(keyFile, password);
	return true;
}

namespace Common {
namespace CLI {
template<>
int ValGetter<Command &>::get(const std::vector<Common::UString> &args, int i, int) {
	_val = kCommandNone;
	for (int j = 0; j < kCommandMAX; j++) {
		if (!strcmp(args[i].c_str(), kCommandChar[j])) {
			_val = (Command) j;
			return 0;
		}
	}
	return -1;
}
}
}

bool parseCommandLine(const std::vector<Common::UString> &argv, int &returnValue,
                      Command &command, Common::UString &archive, std::set<Common::UString> &files,
                      Aurora::GameID &game, std::vector<byte> &password) {

	using Common::CLI::NoOption;
	using Common::CLI::kContinueParsing;
	using Common::CLI::Parser;
	using Common::CLI::Callback;
	using Common::CLI::ValGetter;
	using Common::CLI::ValAssigner;
	using Common::CLI::makeEndArgs;
	using Common::CLI::makeAssigners;
	using Aurora::GameID;

	NoOption cmdOpt(false, new ValGetter<Command &>(command, "command"));
	NoOption archiveOpt(false, new ValGetter<Common::UString &>(archive, "archive"));
	NoOption filesOpt(true, new ValGetter<std::set<Common::UString> &>(files, "files[...]"));
	Parser parser(argv[0], "BioWare ERF (.erf, .mod, .nwm, .sav) archive extractor",
	              "Commands:\n"
	              "  i          Display meta-information\n"
	              "  l          List files (stripping directories)\n"
	              "  v          List files verbosely (with directories)\n"
	              "  e          Extract files to current directory, stripping directories\n"
	              "  x          Extract files to current directory, creating subdirectories\n",
	              returnValue,
	              makeEndArgs(&cmdOpt, &archiveOpt, &filesOpt));

	parser.addSpace();
	parser.addOption("nwn2", "Alias file types according to Neverwinter Nights 2 rules",
	                 kContinueParsing,
	                 makeAssigners(new ValAssigner<GameID>(Aurora::kGameIDNWN2, game)));
	parser.addOption("jade", "Alias file types according to Jade Empire rules",
	                 kContinueParsing,
	                 makeAssigners(new ValAssigner<GameID>(Aurora::kGameIDJade, game)));
	parser.addSpace();
	parser.addOption("pass", "Decryption password, if required, in hex notation",
	                 kContinueParsing,
	                 new Callback<std::vector<byte> &>("hex", parsePassword, password));
	parser.addOption("nwn",
	                 "Neverwinter Nights premium module file(for decrypting their HAK file)",
	                 kContinueParsing,
	                 new Callback<std::vector<byte> &>("file", readNWMMD5, password));

	return parser.process(argv);
}

void displayInfo(Aurora::ERFFile &erf) {
	std::printf("Version: %s\n", Common::debugTag(erf.getVersion()).c_str());
	std::printf("Build Year: %d\n", erf.getBuildYear());
	std::printf("Build Day: %d\n", erf.getBuildDay());
	std::printf("Number of files: %s\n", Common::composeString(erf.getResources().size()).c_str());


	const Aurora::LocString &description = erf.getDescription();
	if (description.getString().empty() && (description.getID() == Aurora::kStrRefInvalid))
		return;

	std::printf("\nDescription:\n");
	std::printf("String reference ID: %u\n", description.getID());

	std::vector<Aurora::LocString::SubLocString> str;
	description.getStrings(str);

	for (std::vector<Aurora::LocString::SubLocString>::iterator s = str.begin(); s != str.end(); ++s) {
		std::printf("\n.=== Description in language %u: ===\n", s->language);
		std::printf("%s\n", s->str.c_str());
		std::printf("'=== ===\n");
	}
}
