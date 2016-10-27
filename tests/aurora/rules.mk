# xoreos-tools - Tools to help with xoreos development
#
# xoreos-tools is the legal property of its developers, whose names
# can be found in the AUTHORS file distributed with this source
# distribution.
#
# xoreos-tools is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version.
#
# xoreos-tools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with xoreos-tools. If not, see <http://www.gnu.org/licenses/>.

# Unit tests for the Aurora namespace.

aurora_LIBS = \
    $(test_LIBS) \
    src/aurora/libaurora.la \
    src/common/libcommon.la \
    tests/version/libversion.la \
    $(LDADD)

check_PROGRAMS                 += tests/aurora/test_util
tests_aurora_test_util_SOURCES  = tests/aurora/util.cpp
tests_aurora_test_util_LDADD    = $(aurora_LIBS)
tests_aurora_test_util_CXXFLAGS = $(test_CXXFLAGS)

check_PROGRAMS                     += tests/aurora/test_language
tests_aurora_test_language_SOURCES  = tests/aurora/language.cpp
tests_aurora_test_language_LDADD    = $(aurora_LIBS)
tests_aurora_test_language_CXXFLAGS = $(test_CXXFLAGS)

check_PROGRAMS                      += tests/aurora/test_locstring
tests_aurora_test_locstring_SOURCES  = tests/aurora/locstring.cpp
tests_aurora_test_locstring_LDADD    = $(aurora_LIBS)
tests_aurora_test_locstring_CXXFLAGS = $(test_CXXFLAGS)

check_PROGRAMS                    += tests/aurora/test_ssffile
tests_aurora_test_ssffile_SOURCES  = tests/aurora/ssffile.cpp
tests_aurora_test_ssffile_LDADD    = $(aurora_LIBS)
tests_aurora_test_ssffile_CXXFLAGS = $(test_CXXFLAGS)

check_PROGRAMS                      += tests/aurora/test_smallfile
tests_aurora_test_smallfile_SOURCES  = tests/aurora/smallfile.cpp
tests_aurora_test_smallfile_LDADD    = $(aurora_LIBS)
tests_aurora_test_smallfile_CXXFLAGS = $(test_CXXFLAGS)

check_PROGRAMS                    += tests/aurora/test_rimfile
tests_aurora_test_rimfile_SOURCES  = tests/aurora/rimfile.cpp
tests_aurora_test_rimfile_LDADD    = $(aurora_LIBS)
tests_aurora_test_rimfile_CXXFLAGS = $(test_CXXFLAGS)