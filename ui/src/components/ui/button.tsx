import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { type VariantProps } from "class-variance-authority"
import { buttonVariants } from "./button.config" // Import from config file

import { cn } from "@/lib/utils"

// Define props interface
export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
  VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

// Wrap component with React.forwardRef
const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button"
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref} // Pass the ref
        {...props}
      />
    )
  }
)
Button.displayName = "Button" // Add display name for better debugging

export { Button } // Only export the component
