import { cva } from "class-variance-authority"

export const sidebarMenuButtonVariants = cva(
  "relative flex h-9 w-full items-center justify-start gap-2 rounded-md px-3 text-sm outline-none transition-colors duration-100 focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default:
          "bg-sidebar text-sidebar-foreground hover:bg-sidebar-hover aria-[current=page]:bg-sidebar-active aria-[current=page]:text-sidebar-active-foreground",
        secondary:
          "bg-transparent text-sidebar-foreground hover:bg-sidebar-muted aria-[current=page]:bg-sidebar-muted aria-[current=page]:text-sidebar-active-foreground",
        ghost:
          "bg-transparent text-sidebar-foreground hover:bg-sidebar-hover aria-[current=page]:bg-sidebar-hover aria-[current=page]:text-sidebar-active-foreground",
        link:
          "h-auto justify-start p-0 text-sidebar-foreground hover:text-sidebar-hover aria-[current=page]:text-sidebar-active-foreground",
      },
      size: {
        default: "h-9",
        sm: "h-8",
        lg: "h-10",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)
