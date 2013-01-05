{
  'targets': [
    {
      'target_name': 'pcap',
      'sources': [
        'src/binding.cc',
      ],
      'conditions': [
        [ 'OS=="win"', {
          'include_dirs': [
            'deps/winpcap/Include',
          ],
          'link_settings': {
            'libraries': ['ws2_32.lib'],
          },
          'defines': [
            'WPCAP',
          ],
          'conditions': [
            [ 'target_arch=="ia32"', {
              'link_settings': {
                'libraries': ['<(PRODUCT_DIR)/../../deps/winpcap/Lib/wpcap.lib'],
              },
            }, {
              'link_settings': {
                'libraries': ['<(PRODUCT_DIR)/../../deps/winpcap/Lib/x64/wpcap.lib'],
              },
            }],
          ],
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