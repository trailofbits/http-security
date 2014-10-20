require 'spec_helper'
require 'security_headers/parser'

describe Parser do
    describe 'General parsing' do
    subject { described_class.new.security_headers }

    it 'parses excess whitespace' do
      header = ' X-Frame-Options : sameorigin '
      expect(subject.parse header).to eq([
        {x_frame_options: 'sameorigin'}
      ])
    end

    it 'handles double quoted directive values' do
      header = 'Strict-Transport-Security: max-age="0"; includeSubDomains'
      expect(subject.parse header).to eq([
        {strict_transport_security: 'max-age="0"; includeSubDomains'}
      ])
    end

    it 'handles singled quoted directive values' do
      header = "Strict-Transport-Security: max-age='0'; includeSubDomains"
      expect(subject.parse header).to eq([
        {strict_transport_security: "max-age='0'; includeSubDomains"}
      ])
    end
  end

  describe 'X-Frames-Options' do
    subject { described_class.new.security_headers }

    it 'parses deny' do
      header = 'X-Frame-Options: deny'
      expect(subject.parse header).to eq([
        {x_frame_options: 'deny'}
      ])
    end

    it 'parses allow-from' do
      header = 'X-Frame-Options: allow-from http://www.example.com'
      expect(subject.parse header).to eq([
        {x_frame_options: 'allow-from http://www.example.com'}
      ])
    end

    it 'parses sameorigin' do
      header = 'X-Frame-Options: sameorigin'
      expect(subject.parse header).to eq([
        {x_frame_options: 'sameorigin'}
      ])
    end
  end

  describe 'Strict-Transport-Security' do
    subject { described_class.new.security_headers }

    it 'accepts only max-age' do
      header = 'Strict-Transport-Security: max-age=31536000'
      expect(subject.parse header).to eq([
        {strict_transport_security: 'max-age=31536000'}
      ])
    end

    it 'accepts max-age of zero' do
      header = 'Strict-Transport-Security: max-age=0'
      expect(subject.parse header).to eq([
        {strict_transport_security: 'max-age=0'}
      ])
    end

    it 'accepts max-age then includeSubdomains' do
      header = 'Strict-Transport-Security: max-age=0; includeSubDomains'
      expect(subject.parse header).to eq([
        {strict_transport_security: 'max-age=0; includeSubDomains'}
      ])
    end

    it 'accepts includeSubdomains then max-age' do
      header = 'Strict-Transport-Security: includeSubDomains; max-age=0'
      expect(subject.parse header).to eq([
        {strict_transport_security: 'includeSubDomains; max-age=0'}
      ])
    end
  end

  describe 'X-Content-Type-Options' do
    subject { described_class.new.security_headers }

    it 'accepts nosniff' do
      header = 'X-Content-Type-Options: nosniff'
      expect(subject.parse header).to eq([
        { x_content_type_options: 'nosniff'}
      ])
    end
  end

  describe 'X-XSS-Protection' do
    subject { described_class.new.security_headers }

    it 'it accepts 1; mode=block' do
      header = 'X-XSS-Protection: 1; mode=block'
      expect(subject.parse header).to eq([
        { x_xss_protection: '1; mode=block' }
      ])
    end

    it 'it accepts 0; mode=block' do
      header = 'X-XSS-Protection: 0; mode=block'
      expect(subject.parse header).to eq([
        { x_xss_protection: '0; mode=block' }
      ])
    end

    it 'it accepts 1' do
      header = 'X-XSS-Protection: 1'
      expect(subject.parse header).to eq([
        { x_xss_protection: '1' }
      ])
    end
  end

  describe 'Cache-Control' do
    subject { described_class.new.security_headers }

    it 'it accepts private' do
      header = 'Cache-Control: private'
      expect(subject.parse header).to eq([
        { cache_control: 'private' }
      ])
    end

    it 'it accepts public, max-age=1' do
      header = 'Cache-Control: public, max-age=1'
      expect(subject.parse header).to eq([
        { cache_control: 'public, max-age=1' }
      ])
    end

    it 'it accepts all recommended value: private, max-age=0, no-cache' do
      header = 'Cache-Control: private, max-age=0, no-cache'
      expect(subject.parse header).to eq([
        { cache_control: 'private, max-age=0, no-cache' }
      ])
    end
  end

end
