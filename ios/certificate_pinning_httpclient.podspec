Pod::Spec.new do |s|
  s.name             = 'certificate_pinning_httpclient'
  s.version          = '0.0.1'
  s.summary          = 'Flutter plugin for certificate pinning.'
  s.description      = <<-DESC
A Flutter plugin that uses certificate pinning via SPKI hashes.
                       DESC
  s.license          = { :type => 'BSD', :file => '../LICENSE' }
  s.author           = { 'skoller' => 'seb.koller@gmail.com' }
  s.source           = { :http => 'https://github.com/sebkoller/certificate_pinning_httpclient' }
  s.homepage         - 'https://github.com/sebkoller/certificate_pinning_httpclient'
  # s.documentation_url = ''
  s.source_files = 'Classes/**/*'
  s.public_header_files = 'Classes/**/*.h'
  s.dependency 'Flutter'
  s.platform = :ios, '10.0'
  # Flutter.framework does not contain an i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
end
