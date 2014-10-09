require 'spec_helper'
require 'security_headers/parser'

describe Parser do
  describe '#x-frames-options' do
    subject { described_class.new.security_headers }
    it 'parses deny' do
      header = 'X-Frame-Options: deny'
      expect(subject.parse header).to eq([
        {x_frame_options: 'deny'}
      ])
    end

    it 'parses sameorigin' do
      header = 'X-Frame-Options: sameorigin'
      expect(subject.parse header).to eq([
        {x_frame_options: 'sameorigin'}
      ])
    end
  end

end
