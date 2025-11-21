#!/bin/bash
# Create placeholder PNG icons using ImageMagick

# Icon 16x16
convert -size 16x16 xc:none -gravity center \
  -fill "#667eea" -draw "circle 8,8 8,2" \
  -fill white -draw "path 'M 5,8 L 7,10 L 11,6'" \
  icon16.png

# Icon 48x48
convert -size 48x48 xc:none -gravity center \
  -fill "#667eea" -draw "circle 24,24 24,6" \
  -fill white -stroke white -strokewidth 2 \
  -draw "path 'M 16,24 L 21,29 L 32,18'" \
  icon48.png

# Icon 128x128
convert -size 128x128 xc:none -gravity center \
  -fill "#667eea" -draw "circle 64,64 64,16" \
  -fill white -stroke white -strokewidth 5 \
  -draw "path 'M 42,64 L 56,78 L 86,48'" \
  icon128.png

echo "Icons created successfully!"
