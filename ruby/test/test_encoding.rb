# frozen_string_literal: true

# RUN: ruby test/test_encoding.rb
#
# A process with no LANG gets a C locale, and Ruby then tags what it reads
# as US-ASCII. Every read of a stored secret must come back as UTF-8 anyway.

require 'fileutils'
require 'minitest/autorun'
require 'tmpdir'

require_relative 'pluginhome'

pluginpath

require_relative '../lib/voxgig_sekreto'
require_relative '../lib/voxgig_sekreto/plugins/boru'

TOKEN = "tökén"

class TestEncoding < Minitest::Test
  def setup
    @external = Encoding.default_external
    Encoding.default_external = Encoding::US_ASCII
    @dir = Dir.mktmpdir('sekreto-encoding')
  end

  def teardown
    Encoding.default_external = @external
    FileUtils.remove_entry(@dir)
  end

  def test_dotenv_reads_utf8_under_a_c_locale
    file = File.join(@dir, 'sec.env')
    File.binwrite(file, "API_TOKEN=#{TOKEN}\n")
    assert_equal TOKEN, VoxgigSekreto::DotenvProvider.new(file).lookup('api.token')
  end

  def test_file_reads_utf8_under_a_c_locale
    File.binwrite(File.join(@dir, 'API_TOKEN'), TOKEN)
    assert_equal TOKEN, VoxgigSekreto::FileProvider.new(@dir).lookup('api.token')
  end

  def test_boru_reads_utf8_under_a_c_locale
    command = File.join(@dir, 'boru')
    octal = TOKEN.bytes.map { |b| format('\\%03o', b) }.join
    File.write(command, "#!/bin/sh\nprintf '#{octal}\\n'\n")
    File.chmod(0o755, command)
    assert_equal TOKEN, VoxgigSekreto::BoruProvider.new(command).lookup('api.token')
  end
end
