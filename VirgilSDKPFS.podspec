Pod::Spec.new do |s|
  s.name                  = "VirgilSDKPFS"
  s.version               = "1.2.1"
  s.summary               = "Virgil SDK PFS for Apple devices and languages."
  s.cocoapods_version     = ">= 0.36"
  s.homepage              = "https://github.com/VirgilSecurity/virgil-sdk-pfs-x/"
  s.license               = { :type => "BSD", :file => "LICENSE" }
  s.author                = { "Oleksandr Deundiak" => "deundiak@gmail.com" }
  s.platforms             = { :ios => "8.0", :osx => "10.10" }
  s.source                = { :git => "https://github.com/VirgilSecurity/virgil-sdk-pfs-x.git",
                              :tag => s.version }
  s.weak_frameworks       = 'Foundation'
  s.module_name           = 'VirgilSDKPFS'
  s.source_files          = 'Source/**/*.{swift}'
  s.requires_arc          = true
  s.dependency "VirgilSDK", "~> 4.8.0"
end