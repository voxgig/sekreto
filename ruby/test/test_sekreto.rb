# frozen_string_literal: true

# RUN: ruby test/test_sekreto.rb
# RUN-SOME: ruby test/test_sekreto.rb -n test_envkey
#
# The sekreto conformance suite. Every port runs these same groups, from
# the same spec/sekreto.json, through its own voxgig/omni runner.

require 'minitest/autorun'

require_relative '../lib/voxgig_sekreto'

# Find the shared spec directory by walking up from this file.
def specfile(name)
  dir = File.dirname(File.expand_path(__FILE__))
  8.times do
    cand = File.join(dir, 'spec', name)
    return cand if File.exist?(cand)

    dir = File.dirname(dir)
  end
  raise 'sekreto: spec not found: ' + name
end

# omni is a sibling checkout, not a published gem (yet), so it is required
# by path.
def omnihome
  here = File.dirname(File.expand_path(__FILE__))
  cands = [
    ENV.fetch('OMNI_HOME', nil),
    File.join(here, '..', '..', '..', 'omni'),
    File.join(here, '..', '..', '..', '..', 'omni'),
    '/workspace/omni',
    '/home/user/omni'
  ]

  cands.each do |cand|
    return File.expand_path(cand) if cand && File.exist?(File.join(cand, 'spec', 'fib.json'))
  end

  raise 'sekreto: voxgig/omni not found - set OMNI_HOME'
end

require File.join(omnihome, 'ruby', 'lib', 'voxgig_omni')

# Build a Sekreto from the spec's declarative chain description.
def chainof(spec)
  VoxgigSekreto::Sekreto.new('providers' => spec['chain'], 'cache' => false)
end

R = VoxgigOmni.make_runner(specfile('sekreto.json')).call('sekreto')

class TestSekreto < Minitest::Test
  def test_validname
    R[:runsetflags].call(R[:spec]['validname'], { 'null' => false },
                         ->(name) { VoxgigSekreto.validname(name) })
  end

  def test_envkey
    R[:runset].call(R[:spec]['envkey'],
                    ->(vin) { VoxgigSekreto.envkey(vin['name'], vin['prefix']) })
  end

  def test_vaultref
    R[:runset].call(R[:spec]['vaultref'], ->(name) { VoxgigSekreto.vaultref(name) })
  end

  def test_parsedotenv
    R[:runset].call(R[:spec]['parsedotenv'], ->(text) { VoxgigSekreto.parsedotenv(text) })
  end

  def test_resolve
    R[:runset].call(R[:spec]['resolve'], ->(vin) { chainof(vin).get(vin['name']) })
  end

  def test_trysecret
    R[:runset].call(R[:spec]['trysecret'], ->(vin) { chainof(vin).try(vin['name']) })
  end

  def test_sources
    R[:runset].call(R[:spec]['sources'], ->(vin) { chainof(vin).sources })
  end

  def test_stores
    R[:runset].call(R[:spec]['stores'], ->(vin) { chainof(vin).stores })
  end

  def test_getfrom
    R[:runset].call(R[:spec]['getfrom'],
                    ->(vin) { chainof(vin).getfrom(vin['store'], vin['name']) })
  end

  def test_tryfrom
    R[:runset].call(R[:spec]['tryfrom'],
                    ->(vin) { chainof(vin).tryfrom(vin['store'], vin['name']) })
  end

  def test_redact
    R[:runset].call(R[:spec]['redact'],
                    ->(vin) { VoxgigSekreto.redact(vin['text'], vin['values']) })
  end
end
