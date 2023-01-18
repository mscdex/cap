{
  'targets': [
    {
      'target_name': 'cap',
      'sources': [
        'src/binding.cc',
      ],
      'include_dirs': [
        "<!(node -e \"require('nan')\")",
      ],
      'conditions': [
        [ 'OS=="win"', {
          'include_dirs': [
            'deps/winpcap/Include',
          ],
          'defines': [
            'WPCAP',
          ],
          'conditions': [
            [ 'target_arch=="ia32"', {
              'link_settings': {
                'libraries': ['ws2_32.lib', '<(PRODUCT_DIR)/../../deps/winpcap/Lib/wpcap.lib'],
              },
            }, {
              'link_settings': {
                'libraries': ['ws2_32.lib', '<(PRODUCT_DIR)/../../deps/winpcap/Lib/x64/wpcap.lib'],
              },
            }],
          ],
          'msvs_settings': {
            'VCCLCompilerTool': { 'ExceptionHandling': 1 },
            'VCLinkerTool':{
              'DelayLoadDLLs':['wpcap.dll']
            }
          }
        }, {
          # POSIX
          'link_settings': {
            'libraries': ['-lpcap'],
          },
        }],
      ],
    },
  ],
}