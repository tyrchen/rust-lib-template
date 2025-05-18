import * as React from "react"
import * as DialogPrimitive from "@radix-ui/react-dialog"
import { XIcon } from "lucide-react"

import { cn } from "@/lib/utils"

const Dialog = React.forwardRef<
  HTMLDivElement,
  React.ComponentProps<typeof DialogPrimitive.Root>
>(({ ...props }) => {
  return <DialogPrimitive.Root data-slot="dialog" {...props} />
})
Dialog.displayName = "Dialog"

const DialogTrigger = React.forwardRef<
  HTMLButtonElement,
  React.ComponentProps<typeof DialogPrimitive.Trigger>
>(({ ...props }, ref) => {
  return <DialogPrimitive.Trigger data-slot="dialog-trigger" ref={ref} {...props} />
})
DialogTrigger.displayName = "DialogTrigger"

const DialogPortal = React.forwardRef<
  HTMLDivElement,
  React.ComponentProps<typeof DialogPrimitive.Portal>
>(({ ...props }) => {
  return <DialogPrimitive.Portal data-slot="dialog-portal" {...props} />
})
DialogPortal.displayName = "DialogPortal"

const DialogClose = React.forwardRef<
  HTMLButtonElement,
  React.ComponentProps<typeof DialogPrimitive.Close>
>(({ ...props }) => {
  return <DialogPrimitive.Close data-slot="dialog-close" {...props} />
})
DialogClose.displayName = "DialogClose"

function DialogOverlay({
  className,
  ...props
}: React.ComponentProps<typeof DialogPrimitive.Overlay>) {
  return (
    <DialogPrimitive.Overlay
      data-slot="dialog-overlay"
      className={cn(
        "data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 fixed inset-0 z-50 bg-black/50",
        className
      )}
      {...props}
    />
  )
}
DialogOverlay.displayName = "DialogOverlay"

const DialogContent = React.forwardRef<
  HTMLDivElement,
  React.ComponentProps<typeof DialogPrimitive.Content>
>(({ className, children, ...props }, ref) => {
  return (
    <DialogPortal data-slot="dialog-portal">
      <DialogOverlay />
      <DialogPrimitive.Content
        data-slot="dialog-content"
        ref={ref}
        className={cn(
          "bg-background data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 fixed top-[50%] left-[50%] z-50 grid w-full max-w-[calc(100%-2rem)] translate-x-[-50%] translate-y-[-50%] gap-4 rounded-lg border p-6 shadow-lg duration-200 sm:max-w-lg",
          className
        )}
        {...props}
      >
        {children}
        <DialogPrimitive.Close className="ring-offset-background focus:ring-ring data-[state=open]:bg-accent data-[state=open]:text-muted-foreground absolute top-4 right-4 rounded-xs opacity-70 transition-opacity hover:opacity-100 focus:ring-2 focus:ring-offset-2 focus:outline-hidden disabled:pointer-events-none [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4">
          <XIcon />
          <span className="sr-only">Close</span>
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPortal>
  )
})
DialogContent.displayName = "DialogContent"

function DialogHeader({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="dialog-header"
      className={cn("flex flex-col gap-2 text-center sm:text-left", className)}
      {...props}
    />
  )
}

function DialogFooter({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="dialog-footer"
      className={cn(
        "flex flex-col-reverse gap-2 sm:flex-row sm:justify-end",
        className
      )}
      {...props}
    />
  )
}

const DialogTitle = React.forwardRef<
  HTMLHeadingElement,
  React.ComponentProps<typeof DialogPrimitive.Title>
>(({ className, ...props }, ref) => {
  return (
    <DialogPrimitive.Title
      data-slot="dialog-title"
      ref={ref}
      className={cn("text-lg font-semibold leading-none", className)}
      {...props}
    />
  )
})
DialogTitle.displayName = "DialogTitle"

const DialogDescription = React.forwardRef<
  HTMLParagraphElement,
  React.ComponentProps<typeof DialogPrimitive.Description>
>(({ className, ...props }, ref) => {
  return (
    <DialogPrimitive.Description
      data-slot="dialog-description"
      ref={ref}
      className={cn("text-sm text-muted-foreground", className)}
      {...props}
    />
  )
})
DialogDescription.displayName = "DialogDescription"

export {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogOverlay,
  DialogPortal,
  DialogTitle,
  DialogTrigger,
}
