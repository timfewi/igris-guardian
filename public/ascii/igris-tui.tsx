import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';

// Color themes - edit these values to customize for each background type
// COLORS_DARK is used when hasDarkBackground={true} (default)
// COLORS_LIGHT is used when hasDarkBackground={false}
const COLORS_DARK: Record<string, string> = {
  c0: '#F08080',
  c1: '#A52A2A',
  c2: '#CD5C5C',
  c3: '#FA8072',
};

const COLORS_LIGHT: Record<string, string> = {
  c0: '#482626',
  c1: '#A52A2A',
  c2: '#CD5C5C',
  c3: '#4b2622',
};

type FrameData = {
  duration: number;
  content: string[];
  fgColors: Record<string, string>;
  bgColors: Record<string, string>;
};

type PlaybackAPI = {
  play: () => void;
  pause: () => void;
  restart: () => void;
};

type IgrisTuiProps = {
  hasDarkBackground?: boolean;
  autoPlay?: boolean;
  loop?: boolean;
  onReady?: (api: PlaybackAPI) => void;
};

const FRAMES: FrameData[] = [
  {
    "duration": 83.33333333333333,
    "content": [
      "                                        ",
      "                                        ",
      "                   1                    ",
      "                  .Y;                   ",
      "                  ]Yi                   ",
      "                  ff?                   ",
      "                 ]?'j[                  ",
      "                  fi)                   ",
      "                  ]U[                   ",
      "              l)   m   <,               ",
      "           _,{[    '    ()l             ",
      "         .)fY      |      YTc,          ",
      "       .<m        !|        *T>,        ",
      "      ]U          |il         'm[       ",
      "      ]s         !s!m[         ]r       ",
      "      ][         {U|U|         j[       ",
      "      ]s      .{ !s|m  j       ]r       ",
      "      ]s     |jU  ];[ -UT[     ][       ",
      "      ][    )m(U?  U !fU]|[    ][       ",
      "      ]s     (|{Y)   {[jUY     ][       ",
      "      ]s    l  l{Ul ]ij[ .[    ][       ",
      "      ][    ]T   YUfUF   j[    ][       ",
      "      ][    !|Ti  !U[  |[j[    ][       ",
      "      ]i     j[ |[!m ]m ][     ][       ",
      "      ][     ]| ][ f ][ Ui     ][       ",
      "      ][    -Um ][   ][]mm     ][       ",
      "      !j      f ]] . [[][     .U[       ",
      "       !j[      ]| i m[      .j(        ",
      "        !i[     (U [ m[     ||          ",
      "          (l    !m i U     ][           ",
      "           ji    j i [    ]|            ",
      "            j|   ] i    .][             ",
      "             !i    i   .i               ",
      "               m.  i  .j                ",
      "                ([ j !|                 ",
      "                 ! i !                  ",
      "                   j                    ",
      "                   !                    ",
      "                                        ",
      "                                        "
    ],
    "fgColors": {
      "19,2": "c0",
      "18,3": "c1",
      "19,3": "c0",
      "20,3": "c1",
      "18,4": "c0",
      "19,4": "c2",
      "20,4": "c2",
      "18,5": "c0",
      "19,5": "c1",
      "20,5": "c0",
      "17,6": "c0",
      "18,6": "c2",
      "19,6": "c1",
      "20,6": "c0",
      "21,6": "c2",
      "18,7": "c0",
      "19,7": "c2",
      "20,7": "c0",
      "18,8": "c2",
      "19,8": "c0",
      "20,8": "c1",
      "14,9": "c1",
      "15,9": "c0",
      "19,9": "c0",
      "23,9": "c0",
      "24,9": "c1",
      "11,10": "c1",
      "12,10": "c0",
      "13,10": "c0",
      "14,10": "c0",
      "19,10": "c1",
      "24,10": "c0",
      "25,10": "c0",
      "26,10": "c2",
      "9,11": "c1",
      "10,11": "c0",
      "11,11": "c0",
      "12,11": "c2",
      "19,11": "c0",
      "26,11": "c0",
      "27,11": "c0",
      "28,11": "c0",
      "29,11": "c1",
      "7,12": "c2",
      "8,12": "c0",
      "9,12": "c0",
      "18,12": "c2",
      "19,12": "c2",
      "28,12": "c1",
      "29,12": "c0",
      "30,12": "c0",
      "31,12": "c1",
      "6,13": "c0",
      "7,13": "c0",
      "18,13": "c2",
      "19,13": "c2",
      "20,13": "c2",
      "30,13": "c1",
      "31,13": "c2",
      "32,13": "c1",
      "6,14": "c0",
      "7,14": "c0",
      "17,14": "c0",
      "18,14": "c2",
      "19,14": "c1",
      "20,14": "c2",
      "21,14": "c1",
      "31,14": "c3",
      "32,14": "c1",
      "6,15": "c0",
      "7,15": "c0",
      "17,15": "c2",
      "18,15": "c2",
      "19,15": "c1",
      "20,15": "c2",
      "21,15": "c2",
      "31,15": "c0",
      "32,15": "c1",
      "6,16": "c0",
      "7,16": "c0",
      "14,16": "c1",
      "15,16": "c0",
      "17,16": "c1",
      "18,16": "c2",
      "19,16": "c1",
      "20,16": "c2",
      "23,16": "c0",
      "31,16": "c3",
      "32,16": "c1",
      "6,17": "c0",
      "7,17": "c0",
      "13,17": "c0",
      "14,17": "c0",
      "15,17": "c0",
      "18,17": "c2",
      "19,17": "c2",
      "20,17": "c1",
      "22,17": "c1",
      "23,17": "c0",
      "24,17": "c0",
      "25,17": "c1",
      "31,17": "c3",
      "32,17": "c1",
      "6,18": "c0",
      "7,18": "c0",
      "12,18": "c0",
      "13,18": "c0",
      "14,18": "c1",
      "15,18": "c0",
      "16,18": "c0",
      "19,18": "c2",
      "21,18": "c1",
      "22,18": "c3",
      "23,18": "c0",
      "24,18": "c2",
      "25,18": "c3",
      "26,18": "c1",
      "31,18": "c2",
      "32,18": "c1",
      "6,19": "c0",
      "7,19": "c0",
      "13,19": "c2",
      "14,19": "c3",
      "15,19": "c1",
      "16,19": "c0",
      "17,19": "c0",
      "21,19": "c0",
      "22,19": "c2",
      "23,19": "c0",
      "24,19": "c2",
      "25,19": "c3",
      "31,19": "c3",
      "32,19": "c1",
      "6,20": "c0",
      "7,20": "c0",
      "12,20": "c0",
      "15,20": "c3",
      "16,20": "c0",
      "17,20": "c0",
      "18,20": "c0",
      "20,20": "c3",
      "21,20": "c0",
      "22,20": "c0",
      "23,20": "c3",
      "25,20": "c1",
      "26,20": "c3",
      "31,20": "c2",
      "32,20": "c1",
      "6,21": "c0",
      "7,21": "c3",
      "12,21": "c2",
      "13,21": "c3",
      "17,21": "c3",
      "18,21": "c0",
      "19,21": "c0",
      "20,21": "c0",
      "21,21": "c3",
      "25,21": "c2",
      "26,21": "c0",
      "31,21": "c2",
      "32,21": "c1",
      "6,22": "c0",
      "7,22": "c3",
      "12,22": "c3",
      "13,22": "c0",
      "14,22": "c2",
      "15,22": "c0",
      "18,22": "c2",
      "19,22": "c3",
      "20,22": "c1",
      "23,22": "c2",
      "24,22": "c2",
      "25,22": "c2",
      "26,22": "c1",
      "31,22": "c2",
      "32,22": "c1",
      "6,23": "c3",
      "7,23": "c3",
      "13,23": "c2",
      "14,23": "c1",
      "16,23": "c2",
      "17,23": "c2",
      "18,23": "c1",
      "19,23": "c2",
      "21,23": "c0",
      "22,23": "c2",
      "24,23": "c2",
      "25,23": "c2",
      "31,23": "c2",
      "32,23": "c1",
      "6,24": "c3",
      "7,24": "c2",
      "13,24": "c2",
      "14,24": "c2",
      "16,24": "c2",
      "17,24": "c0",
      "19,24": "c2",
      "21,24": "c2",
      "22,24": "c2",
      "24,24": "c2",
      "25,24": "c2",
      "31,24": "c2",
      "32,24": "c1",
      "6,25": "c3",
      "7,25": "c2",
      "12,25": "c1",
      "13,25": "c2",
      "14,25": "c2",
      "16,25": "c2",
      "17,25": "c2",
      "21,25": "c2",
      "22,25": "c1",
      "23,25": "c2",
      "24,25": "c2",
      "25,25": "c2",
      "31,25": "c2",
      "32,25": "c1",
      "6,26": "c3",
      "7,26": "c2",
      "14,26": "c2",
      "16,26": "c2",
      "17,26": "c2",
      "19,26": "c1",
      "21,26": "c2",
      "22,26": "c1",
      "23,26": "c2",
      "24,26": "c2",
      "30,26": "c1",
      "31,26": "c2",
      "32,26": "c1",
      "7,27": "c1",
      "8,27": "c2",
      "9,27": "c1",
      "16,27": "c2",
      "17,27": "c2",
      "19,27": "c2",
      "21,27": "c2",
      "22,27": "c2",
      "29,27": "c2",
      "30,27": "c2",
      "31,27": "c1",
      "8,28": "c1",
      "9,28": "c2",
      "10,28": "c2",
      "16,28": "c2",
      "17,28": "c2",
      "19,28": "c2",
      "21,28": "c2",
      "22,28": "c2",
      "28,28": "c2",
      "29,28": "c2",
      "10,29": "c2",
      "11,29": "c0",
      "16,29": "c1",
      "17,29": "c2",
      "19,29": "c2",
      "21,29": "c2",
      "27,29": "c2",
      "28,29": "c2",
      "11,30": "c2",
      "12,30": "c2",
      "17,30": "c2",
      "19,30": "c2",
      "21,30": "c2",
      "26,30": "c2",
      "27,30": "c2",
      "12,31": "c2",
      "13,31": "c2",
      "17,31": "c2",
      "19,31": "c2",
      "24,31": "c1",
      "25,31": "c2",
      "26,31": "c1",
      "13,32": "c2",
      "14,32": "c2",
      "19,32": "c2",
      "23,32": "c1",
      "24,32": "c2",
      "15,33": "c2",
      "16,33": "c1",
      "19,33": "c2",
      "22,33": "c2",
      "23,33": "c2",
      "16,34": "c2",
      "17,34": "c2",
      "19,34": "c2",
      "21,34": "c2",
      "22,34": "c2",
      "17,35": "c2",
      "19,35": "c2",
      "21,35": "c2",
      "19,36": "c2",
      "19,37": "c2"
    },
    "bgColors": {}
  }
];

const CANVAS_WIDTH = 40;
const CANVAS_HEIGHT = 40;
const DEFAULT_LOOP = true;

export const IgrisTui: React.FC<IgrisTuiProps> = ({
  hasDarkBackground = true,
  autoPlay = true,
  loop = DEFAULT_LOOP,
  onReady,
}) => {
  const [frameIndex, setFrameIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(autoPlay);
  const frameElapsedRef = useRef(0);
  const lastTimestampRef = useRef(Date.now());

  // Select color theme based on background
  const colors = useMemo(() => hasDarkBackground ? COLORS_DARK : COLORS_LIGHT, [hasDarkBackground]);
  const getColor = useCallback((key: string): string => colors[key] || key, [colors]);
  const defaultFg = hasDarkBackground ? "white" : "black";

  const play = useCallback(() => setIsPlaying(true), []);
  const pause = useCallback(() => setIsPlaying(false), []);
  const restart = useCallback(() => {
    setFrameIndex(0);
    frameElapsedRef.current = 0;
    lastTimestampRef.current = Date.now();
    setIsPlaying(true);
  }, []);

  useEffect(() => {
    if (onReady) {
      onReady({ play, pause, restart });
    }
  }, [onReady, play, pause, restart]);

  useEffect(() => {
    if (!isPlaying || FRAMES.length <= 1) return;

    const interval = setInterval(() => {
      const now = Date.now();
      const delta = now - lastTimestampRef.current;
      lastTimestampRef.current = now;
      frameElapsedRef.current += delta;

      const currentFrame = FRAMES[frameIndex];
      if (frameElapsedRef.current >= currentFrame.duration) {
        frameElapsedRef.current = 0;
        const nextIndex = frameIndex + 1;
        if (nextIndex >= FRAMES.length) {
          if (loop) {
            setFrameIndex(0);
          } else {
            setIsPlaying(false);
          }
        } else {
          setFrameIndex(nextIndex);
        }
      }
    }, 16);

    return () => clearInterval(interval);
  }, [isPlaying, frameIndex, loop]);

  const frame = FRAMES[frameIndex];

  return (
    <box flexDirection="column">
      {frame.content.map((row, y) => (
        <text key={y}>
          {row.split("").map((char, x) => {
            const posKey = `${x},${y}`;
            const fg = frame.fgColors[posKey] ? getColor(frame.fgColors[posKey]) : defaultFg;
            const bg = frame.bgColors[posKey] ? getColor(frame.bgColors[posKey]) : undefined;
            return (
              <span key={x} fg={fg} bg={bg}>
                {char}
              </span>
            );
          })}
        </text>
      ))}
    </box>
  );
};

export default IgrisTui;
