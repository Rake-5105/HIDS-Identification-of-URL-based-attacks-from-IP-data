"use client";

import { cva } from "class-variance-authority";
import { motion, type HTMLMotionProps } from "motion/react";

import { cn } from "../utils";

const waveLoaderVariants = cva("flex gap-2 items-center justify-center", {
  variants: {
    messagePlacement: {
      bottom: "flex-col",
      right: "flex-row",
      left: "flex-row-reverse",
    },
  },
  defaultVariants: {
    messagePlacement: "bottom",
  },
});

export interface WaveLoaderProps {
  /**
   * The number of bouncing bars to display.
   * @default 5
   */
  bars?: number;
  /**
   * Optional message to display alongside the bars.
   */
  message?: string;
  /**
   * Position of the message relative to the spinner.
   * @default bottom
   */
  messagePlacement?: "bottom" | "left" | "right";
  /**
   * Optional class for individual bars.
   */
  barClassName?: string;
}

export function WaveLoader({
  bars = 5,
  message,
  messagePlacement,
  barClassName,
  className,
  ...props
}: HTMLMotionProps<"div"> & WaveLoaderProps) {
  return (
    <div className={cn(waveLoaderVariants({ messagePlacement }), className)}>
      <div className={cn("flex gap-1 items-center justify-center")}>
        {Array(bars)
          .fill(undefined)
          .map((_, index) => (
            <motion.div
              key={index}
              className={cn("w-2 h-5 bg-red-800 dark:bg-red-700 origin-bottom rounded-sm will-change-transform", barClassName)}
              animate={{ scaleY: [0.65, 1.15, 0.65], opacity: [0.55, 1, 0.55] }}
              transition={{
                duration: 0.9,
                repeat: Number.POSITIVE_INFINITY,
                delay: index * 0.1,
                ease: "easeInOut",
              }}
              {...props}
            />
          ))}
      </div>
      {message && <div>{message}</div>}
    </div>
  );
}
